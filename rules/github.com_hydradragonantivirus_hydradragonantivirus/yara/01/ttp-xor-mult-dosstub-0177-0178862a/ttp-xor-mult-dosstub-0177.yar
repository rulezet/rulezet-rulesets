rule TTP_XOR_MULT_DOSStub_0177 {
  strings:
    $key_0177 = { 55 1f [2] 21 07 [2] 66 05 [2] 21 14 [2] 6f 18 [2] 63 12 [2] 74 19 [2] 6f 57 [2] 52 }

  condition:
    any of them
}