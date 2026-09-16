rule TTP_XOR_MULT_DOSStub_0156 {
  strings:
    $key_0156 = { 55 3e [2] 21 26 [2] 66 24 [2] 21 35 [2] 6f 39 [2] 63 33 [2] 74 38 [2] 6f 76 [2] 52 }

  condition:
    any of them
}