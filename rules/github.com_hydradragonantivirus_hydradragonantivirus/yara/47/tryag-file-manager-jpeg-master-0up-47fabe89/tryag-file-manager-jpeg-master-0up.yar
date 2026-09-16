rule Tryag_File_Manager_jpeg_master_0up {
  meta:
    description = "Tryag-File-Manager-jpeg-master - file 0up.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-14"
    hash1       = "083c429dc1ffeabbd474429b573c40d6f395b1765409fbb9e63c98f05c1fb80d"

  strings:
    $s1 = "<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">';" fullword ascii
        
  condition:
    (uint16(0) == 0x743c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}