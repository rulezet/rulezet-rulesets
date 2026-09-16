rule TTP_XOR_MULT_DOSStub_0151 {
  strings:
    $key_0151 = { 55 39 [2] 21 21 [2] 66 23 [2] 21 32 [2] 6f 3e [2] 63 34 [2] 74 3f [2] 6f 71 [2] 52 }

  condition:
    any of them
}