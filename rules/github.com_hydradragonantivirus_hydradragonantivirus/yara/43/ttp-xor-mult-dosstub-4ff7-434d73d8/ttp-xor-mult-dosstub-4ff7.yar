rule TTP_XOR_MULT_DOSStub_4ff7 {
  strings:
    $key_4ff7 = { 1b 9f [2] 6f 87 [2] 28 85 [2] 6f 94 [2] 21 98 [2] 2d 92 [2] 3a 99 [2] 21 d7 [2] 1c }

  condition:
    any of them
}