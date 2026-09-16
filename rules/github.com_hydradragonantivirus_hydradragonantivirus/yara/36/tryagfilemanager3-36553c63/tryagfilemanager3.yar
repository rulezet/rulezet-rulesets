rule TryagFileManager3 {
  meta:
    description = "Tryag-File-Manager-jpeg-master - file TryagFileManager3.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-14"
    hash1       = "3cf5af7774d1dc7ca7b58d9d6899ef307eabb9ed9b66d4ef0eb44cd346135bd8"

  strings:
    $s1  = "<textarea cols=80 rows=20 name=\"src\">'.htmlspecialchars(file_get_contents($_POST['path'])).'</textarea><br />" fullword ascii
    $s2  = "echo('<pre>'.htmlspecialchars(file_get_contents(base64_decode($_GET['filesrc']))).'</pre>');" fullword ascii
    $s3  = "echo '<br />Tryag File Manager Version <font color=\"red\">1.1</font>, Coded By <font color=\"red\">./ChmoD</font><br />Home: <f" ascii
    $s4  = "<script type=\"text/javascript\" src=\"http://www.codejquery.net/jquery.mins.js\" ></script>" fullword ascii
    $s5  = "echo '<div id=\"content\"><table width=\"700\" border=\"0\" cellpadding=\"3\" cellspacing=\"1\" align=\"center\">" fullword ascii
    $s6  = "echo '<br />Tryag File Manager Version <font color=\"red\">1.1</font>, Coded By <font color=\"red\">./ChmoD</font><br />Home: <f" ascii
    $s7  = "New Name : <input name=\"newname\" type=\"text\" size=\"20\" value=\"'.$_POST['name'].'\" />" fullword ascii
    $s8  = "echo '<font color=\"red\">File Upload Error.</font><br />';" fullword ascii
    $s9  = "<td><center><form method=\\\"POST\\\" action=\\\"?option&path=$pathen\\\">" fullword ascii
    $s10 = "$url=$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];" fullword ascii
    $s11 = "if(is_writable(\"$path/$file\") || !is_readable(\"$path/$file\")) echo '</font>';" fullword ascii
    $s12 = "echo '<font color=\"green\">File Upload Done.</font><br />';" fullword ascii
    $s13 = "<input type=\"hidden\" name=\"path\" value=\"'.$_POST['path'].'\">" fullword ascii
    $s14 = "foreach($_POST as $key=>$value){" fullword ascii
    $s15 = "$_POST[$key] = stripslashes($value);" fullword ascii
    $s16 = "if(is_writable(\"$path/$dir\") || !is_readable(\"$path/$dir\")) echo '</font>';" fullword ascii
    $s17 = "}elseif(isset($_GET['option']) && $_POST['opt'] != 'delete'){" fullword ascii
    $s18 = "if(isset($_GET['option']) && $_POST['opt'] == 'delete'){" fullword ascii
    $s19 = "echo '<form enctype=\"multipart/form-data\" method=\"POST\">" fullword ascii
    $s20 = "if(copy($_FILES['file']['tmp_name'],$path.'/'.$_FILES['file']['name'])){" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 30KB and
      (8 of them)
    ) or (all of them)
}