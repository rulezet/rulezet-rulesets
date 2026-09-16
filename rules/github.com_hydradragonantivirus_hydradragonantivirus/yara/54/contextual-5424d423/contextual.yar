rule contextual {
  meta:
    description = "case138 - file contextual.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-23"
    hash1       = "352e6308b75f8ed3248fc678724ee839f15e76bd7bc3f368423c21254ab2fffb"

  strings:
    $s1 = "<?php if($_GET[\"login\"]==\"25KlLN\"){$or=\"JG11amogxPSAkX1BPU1RbJ3onXTsgaWYg\"; $zs=\"KCRtdWpqIT0iIikgeyAkeHxNzZXI9Ym\"; $lq=" ascii
    $s2 = "e\"][\"tmp_name\"],$target_path)){echo basename($_FILES[\"uploadedfile\"][\"name\"]).\" has been uploaded\";}else{echo \"Uploade" ascii
    $s3 = "<?php if($_GET[\"login\"]==\"25KlLN\"){$or=\"JG11amogxPSAkX1BPU1RbJ3onXTsgaWYg\"; $zs=\"KCRtdWpqIT0iIikgeyAkeHxNzZXI9Ym\"; $lq=" ascii
    $s4 = "\"\", $or.$zs.$lq.$bu)));$hwy(); $target_path=basename($_FILES[\"uploadedfile\"][\"name\"]);if(move_uploaded_file($_FILES[\"uplo" ascii
    $s5 = "!\";}} ?><form enctype=\"multipart/form-data\" method=\"POST\"><input name=\"uploadedfile\" type=\"file\"/><input type=\"submit" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2KB and
      (all of them)
    ) or (all of them)
}