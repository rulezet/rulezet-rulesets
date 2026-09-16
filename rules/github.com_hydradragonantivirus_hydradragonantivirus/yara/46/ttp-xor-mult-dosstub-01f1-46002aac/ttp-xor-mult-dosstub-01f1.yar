rule TTP_XOR_MULT_DOSStub_01f1 {
  strings:
    $key_01f1 = { 55 99 [2] 21 81 [2] 66 83 [2] 21 92 [2] 6f 9e [2] 63 94 [2] 74 9f [2] 6f d1 [2] 52 }

  condition:
    any of them
}