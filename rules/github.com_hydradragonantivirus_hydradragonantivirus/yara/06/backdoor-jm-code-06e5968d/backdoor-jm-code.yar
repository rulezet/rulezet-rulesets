rule backdoor_jm_code {
  meta:
    description = "PHP - file backdoor_jm_code.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "a676e044d250466dfb21e06c7bbf75ccfea523afe77aa2d641a8202acf09af7a"

  strings:
    $s1  = "$cats[$i]->path = get_full_path(JURI::base() . 'index.php?option=com_content&view=category&layout=blog&id=' . $cats[$i]->id);" fullword ascii
    $s2  = "if(!empty($_POST['password']) && md5($_POST['password']) == SHELL_PASSWORD) {" fullword ascii
    $s3  = "setcookie('password', SHELL_PASSWORD, time() + 60*60*24);" fullword ascii
    $s4  = "print '<form method=\"post\">Password : <input type=\"text\" name=\"password\"><input type=\"submit\"></form>';" fullword ascii
    $s5  = "$usersParams = &JComponentHelper::getParams( 'com_users' ); // load the Params" fullword ascii
    $s6  = "$user = JFactory::getUser(0); // it's important to set the \"0\" otherwise your admin user information will be loaded" fullword ascii
    $s7  = "if(empty($_COOKIE) || $_COOKIE['password'] != SHELL_PASSWORD) {" fullword ascii
    $s8  = "define('SHELL_PASSWORD', 'a6a8cb877ee18215f2c0fc2a6c7b4f2a');" fullword ascii
    $s9  = "$sql = \"SELECT path FROM #__menu WHERE link LIKE 'index.php?option=com_content&view=category&%id={$article->catid}' \";" fullword ascii
    $s10 = "define('JPATH_COMPONENT_ADMINISTRATOR', JPATH_BASE . DS . 'administrator' . DS . 'components' . DS . 'com_content');" fullword ascii
    $s11 = "$sql = \"SELECT * FROM #__content WHERE id='\" . $_REQUEST['article_id'].\"'\"; // prepare query" fullword ascii
    $s12 = "if((empty($_COOKIE['password']) && empty($_POST['password'])) || (!empty($_POST['password']) && md5($_POST['password']) != SHELL" ascii
    $s13 = "if((empty($_COOKIE['password']) && empty($_POST['password'])) || (!empty($_POST['password']) && md5($_POST['password']) != SHELL" ascii
    $s14 = "jimport('joomla.application.component.helper'); // include libraries/application/component/helper.php" fullword ascii
    $s15 = "if(!empty($_REQUEST['user_name']) && !empty($_REQUEST['user_password']) && !empty($_REQUEST['user_email'])) {" fullword ascii
    $s16 = "require_once(JPATH_BASE.DS.'components'.DS.'com_content'.DS.'helpers'.DS.'route.php');" fullword ascii
    $s17 = "//echo JPATH_BASE. \"/administrator/components/com_content/models/article.php\";" fullword ascii
    $s18 = "require_once JPATH_BASE. \"/components/com_content/models/article.php\";" fullword ascii
    $s19 = "print '<a href=\"'.$base_name.'\" target=\"_blank\">'.$base_name.'</a>';" fullword ascii
    $s20 = "define('PASSWORD_FILE', 'p.txt');" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 30KB and
      (8 of them)
    ) or (all of them)
}