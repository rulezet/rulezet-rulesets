rule TTP_XOR_MULT_DOSStub_0126 {
  strings:
    $key_0126 = { 55 4e [2] 21 56 [2] 66 54 [2] 21 45 [2] 6f 49 [2] 63 43 [2] 74 48 [2] 6f 06 [2] 52 }

  condition:
    any of them
}