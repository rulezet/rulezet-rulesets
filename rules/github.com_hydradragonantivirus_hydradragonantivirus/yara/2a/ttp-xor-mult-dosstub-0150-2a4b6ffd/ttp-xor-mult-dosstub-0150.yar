rule TTP_XOR_MULT_DOSStub_0150 {
  strings:
    $key_0150 = { 55 38 [2] 21 20 [2] 66 22 [2] 21 33 [2] 6f 3f [2] 63 35 [2] 74 3e [2] 6f 70 [2] 52 }

  condition:
    any of them
}