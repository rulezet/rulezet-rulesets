rule TTP_XOR_MULT_DOSStub_5f65 {
  strings:
    $key_5f65 = { 0b 0d [2] 7f 15 [2] 38 17 [2] 7f 06 [2] 31 0a [2] 3d 00 [2] 2a 0b [2] 31 45 [2] 0c }

  condition:
    any of them
}