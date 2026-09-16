rule TTP_XOR_MULT_DOSStub_0df7 {
  strings:
    $key_0df7 = { 59 9f [2] 2d 87 [2] 6a 85 [2] 2d 94 [2] 63 98 [2] 6f 92 [2] 78 99 [2] 63 d7 [2] 5e }

  condition:
    any of them
}