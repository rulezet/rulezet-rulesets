rule mail_2018 {
  meta:
    description = "Tryag-File-Manager-jpeg-master - file mail-2018.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-14"
    hash1       = "35d176c910d8db75fb752620eec215aa618ba00a74b563d85db5bcd72fc0d710"

  strings:
            $s3  = "//contact: https://www.facebook.com/achraf.orion.1//" fullword ascii
                                                        $s17 = ".log{" fullword ascii
            $s20 = "if (mail($taz, $subj, $mess, $headers)){" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 40KB and
      (8 of them)
    ) or (all of them)
}