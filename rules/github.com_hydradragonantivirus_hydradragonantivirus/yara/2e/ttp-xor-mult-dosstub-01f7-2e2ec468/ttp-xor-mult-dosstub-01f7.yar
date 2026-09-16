rule TTP_XOR_MULT_DOSStub_01f7 {
  strings:
    $key_01f7 = { 55 9f [2] 21 87 [2] 66 85 [2] 21 94 [2] 6f 98 [2] 63 92 [2] 74 99 [2] 6f d7 [2] 52 }

  condition:
    any of them
}