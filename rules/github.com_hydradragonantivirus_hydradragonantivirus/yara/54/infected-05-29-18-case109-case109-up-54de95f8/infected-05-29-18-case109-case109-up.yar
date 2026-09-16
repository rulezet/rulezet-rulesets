rule infected_05_29_18_case109_case109_up {
  meta:
    description = "case109 - file up.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-05-29"
    hash1       = "c726a17e6852eeda1eda467c5725eab693a808445c42ddde0aa4c89018511c38"

  strings:
    $s1  = "if (!empty($_GET['action']) &&  $_GET['action'] == \"logout\") {session_destroy();unset ($_SESSION['pass']);}" fullword ascii
    $s2  = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1256\" /></head><body>" fullword ascii
    $s3  = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">" fullword ascii
    $s4  = "{echo \"Stored file:\".$_FILES[\"file\"][\"name\"].\"<br/>Size:\".($_FILES[\"file\"][\"size\"]/1024).\" kB<br/>\";" fullword ascii
    $s5  = "while($entryName = readdir($myDirectory)) {$dirArray[] = $entryName;} closedir($myDirectory);" fullword ascii
    $s6  = "<form enctype=\"multipart/form-data\" action=\"<?php echo $_SERVER['PHP_SELF']; ?>\" method=\"POST\">" fullword ascii
    $s7  = "if ($_POST['pass'] == $pass) {$_SESSION['pass'] = $pass; }" fullword ascii
    $s8  = "move_uploaded_file($_FILES[\"file\"][\"tmp_name\"],$_FILES[\"file\"][\"name\"]);" fullword ascii
    $s9  = "if (empty($_POST['pass'])) {$_POST['pass']='';}" fullword ascii
    $s10 = "echo '<form action=\"'.$_SERVER['PHP_SELF'].'\" method=\"post\"><input name=\"pass\" type=\"password\"><input type=\"submit\"></" ascii
    $s11 = "echo '<form action=\"'.$_SERVER['PHP_SELF'].'\" method=\"post\"><input name=\"pass\" type=\"password\"><input type=\"submit\"></" ascii
    $s12 = "echo \"<TABLE border=1 cellpadding=5 cellspacing=0 class=whitelinks><TR><TH>Filename</TH><th>Filetype</th><th>Filesize</th></" fullword ascii
    $s13 = "{echo \"Error: \" . $_FILES[\"file\"][\"error\"] . \"<br>\";}" fullword ascii
    $s14 = "if (empty($_SESSION['pass'])) {$_SESSION['pass']='';}" fullword ascii
    $s15 = "Please choose a file: <input name=\"file\" type=\"file\" /><br />" fullword ascii
    $s16 = "<td><a href=\\\"$dirArray[$index]\\\">$dirArray[$index]</a></td>" fullword ascii
    $s17 = "<input type=\"submit\" value=\"Upload\" /></form>" fullword ascii
    $s18 = "$this_script = $path_name['basename'];" fullword ascii
    $s19 = "// get each entry" fullword ascii
    $s20 = "if ($_FILES[\"file\"][\"error\"] > 0)" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 6KB and
      (8 of them)
    ) or (all of them)
}