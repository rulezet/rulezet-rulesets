rule TTP_XOR_MULT_DOSStub_0df1 {
  strings:
    $key_0df1 = { 59 99 [2] 2d 81 [2] 6a 83 [2] 2d 92 [2] 63 9e [2] 6f 94 [2] 78 9f [2] 63 d1 [2] 5e }

  condition:
    any of them
}