rule TTP_XOR_MULT_DOSStub_5313 {
  strings:
    $key_5313 = { 07 7b [2] 73 63 [2] 34 61 [2] 73 70 [2] 3d 7c [2] 31 76 [2] 26 7d [2] 3d 33 [2] 00 }

  condition:
    any of them
}