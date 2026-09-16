rule TTP_XOR_MULT_DOSStub_0141 {
  strings:
    $key_0141 = { 55 29 [2] 21 31 [2] 66 33 [2] 21 22 [2] 6f 2e [2] 63 24 [2] 74 2f [2] 6f 61 [2] 52 }

  condition:
    any of them
}