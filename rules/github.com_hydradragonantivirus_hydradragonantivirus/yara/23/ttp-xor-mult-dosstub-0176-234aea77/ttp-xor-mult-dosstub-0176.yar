rule TTP_XOR_MULT_DOSStub_0176 {
  strings:
    $key_0176 = { 55 1e [2] 21 06 [2] 66 04 [2] 21 15 [2] 6f 19 [2] 63 13 [2] 74 18 [2] 6f 56 [2] 52 }

  condition:
    any of them
}