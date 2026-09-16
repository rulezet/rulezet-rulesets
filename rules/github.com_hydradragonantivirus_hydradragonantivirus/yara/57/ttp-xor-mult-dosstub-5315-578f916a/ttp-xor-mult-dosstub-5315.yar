rule TTP_XOR_MULT_DOSStub_5315 {
  strings:
    $key_5315 = { 07 7d [2] 73 65 [2] 34 67 [2] 73 76 [2] 3d 7a [2] 31 70 [2] 26 7b [2] 3d 35 [2] 00 }

  condition:
    any of them
}