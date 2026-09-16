rule TTP_XOR_MULT_DOSStub_5311 {
  strings:
    $key_5311 = { 07 79 [2] 73 61 [2] 34 63 [2] 73 72 [2] 3d 7e [2] 31 74 [2] 26 7f [2] 3d 31 [2] 00 }

  condition:
    any of them
}