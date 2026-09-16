rule TTP_XOR_MULT_DOSStub_6d63 {
  strings:
    $key_6d63 = { 39 0b [2] 4d 13 [2] 0a 11 [2] 4d 00 [2] 03 0c [2] 0f 06 [2] 18 0d [2] 03 43 [2] 3e }

  condition:
    any of them
}