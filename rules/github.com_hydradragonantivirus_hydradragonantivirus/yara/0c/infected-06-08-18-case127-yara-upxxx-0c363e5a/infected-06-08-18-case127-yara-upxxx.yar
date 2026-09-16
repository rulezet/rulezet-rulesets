rule infected_06_08_18_case127_yara_upxxx {
  meta:
    description = "case127 - file upxxx.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "b364b42e478e199d30b322b60d6d5f478636b311db63344f4adba565dba0c2ee"

  strings:
    $s1 = "@move_uploaded_file($userfile_tmp, $abod);" fullword ascii
    $s2 = "$userfile_tmp = $_FILES['image']['tmp_name'];" fullword ascii
    $s3 = "echo\"<center><b>Done ==> $userfile_name</b></center>\";" fullword ascii
    $s4 = "$userfile_name = $_FILES['image']['name'];" fullword ascii
    $s5 = "if(isset($_POST['Submit'])){" fullword ascii
    $s6 = "$abod = $filedir.$userfile_name;" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}