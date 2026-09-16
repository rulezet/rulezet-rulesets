rule apt32_macos_backdoor_2018_encryption_key {
  strings:
    $key = { 63 49 2f 6e 22 00 10 fe 33 4f 2f c5 05 b2 11 03 ba 5b dd 02 }
    $ccc = "CCCrypt" ascii

  condition:
    (uint16(0) == 0xfacf or uint16(0) == 0xface) and all of them
}