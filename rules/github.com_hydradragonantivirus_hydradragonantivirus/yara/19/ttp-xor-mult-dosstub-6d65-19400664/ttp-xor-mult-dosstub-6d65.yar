rule TTP_XOR_MULT_DOSStub_6d65 {
  strings:
    $key_6d65 = { 39 0d [2] 4d 15 [2] 0a 17 [2] 4d 06 [2] 03 0a [2] 0f 00 [2] 18 0b [2] 03 45 [2] 3e }

  condition:
    any of them
}