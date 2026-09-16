rule TTP_XOR_MULT_DOSStub_6d68 {
  strings:
    $key_6d68 = { 39 00 [2] 4d 18 [2] 0a 1a [2] 4d 0b [2] 03 07 [2] 0f 0d [2] 18 06 [2] 03 48 [2] 3e }

  condition:
    any of them
}