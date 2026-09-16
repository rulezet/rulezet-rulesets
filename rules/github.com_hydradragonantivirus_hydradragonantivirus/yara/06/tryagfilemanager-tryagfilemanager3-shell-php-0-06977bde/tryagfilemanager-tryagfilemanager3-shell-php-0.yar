rule _TryagFileManager_TryagFileManager3_shell_php_0 {
  meta:
    description = "Tryag-File-Manager-jpeg-master - from files TryagFileManager.php, TryagFileManager3.php, shell.php.pjpeg"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-14"
    hash1       = "e32a7a80127f4d5be15a811c9f52b0698f2b73e5d65d48808462b074b9131856"
    hash2       = "3cf5af7774d1dc7ca7b58d9d6899ef307eabb9ed9b66d4ef0eb44cd346135bd8"
    hash3       = "cb2241fd794aaff55b354114d1447e3e6411619ca257316807cb6d0d59651021"

  strings:
    $s1  = "New Name : <input name=\"newname\" type=\"text\" size=\"20\" value=\"'.$_POST['name'].'\" />" fullword ascii
    $s2  = "echo '<font color=\"red\">File Upload Error.</font><br />';" fullword ascii
    $s3  = "echo '<font color=\"green\">File Upload Done.</font><br />';" fullword ascii
    $s4  = "foreach($_POST as $key=>$value){" fullword ascii
    $s5  = "$_POST[$key] = stripslashes($value);" fullword ascii
    $s6  = "echo '<font color=\"red\">Change Permission Error.</font><br />';" fullword ascii
    $s7  = "echo '<font color=\"red\">Delete File Error.</font><br />';" fullword ascii
    $s8  = "echo '<font color=\"red\">Edit File Error.</font><br />';" fullword ascii
    $s9  = "echo '<font color=\"red\">Change Name Error.</font><br />';" fullword ascii
    $s10 = "echo '<font color=\"red\">Delete Dir Error.</font><br />';" fullword ascii
    $s11 = "}elseif($_POST['opt'] == 'rename'){" fullword ascii
    $s12 = "$_POST['name'] = $_POST['newname'];" fullword ascii
    $s13 = "}elseif($_POST['type'] == 'file'){" fullword ascii
    $s14 = "$fp = fopen($_POST['path'],'w');" fullword ascii
    $s15 = "if($_POST['opt'] == 'chmod'){" fullword ascii
    $s16 = "echo '<form method=\"POST\">" fullword ascii
    $s17 = "if(rmdir($_POST['path'])){" fullword ascii
    $s18 = "if(unlink($_POST['path'])){" fullword ascii
    $s19 = "echo '<font color=\"green\">Change Permission Done.</font><br />';" fullword ascii
    $s20 = "Upload File : <input type=\"file\" name=\"file\" />" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 80KB and (8 of them)
    ) or (all of them)
}