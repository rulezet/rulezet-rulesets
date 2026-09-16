rule TTP_XOR_MULT_DOSStub_1d63 {
  strings:
    $key_1d63 = { 49 0b [2] 3d 13 [2] 7a 11 [2] 3d 00 [2] 73 0c [2] 7f 06 [2] 68 0d [2] 73 43 [2] 4e }

  condition:
    any of them
}