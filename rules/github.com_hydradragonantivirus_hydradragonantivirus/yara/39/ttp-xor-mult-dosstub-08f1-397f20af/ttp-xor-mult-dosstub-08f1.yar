rule TTP_XOR_MULT_DOSStub_08f1 {
  strings:
    $key_08f1 = { 5c 99 [2] 28 81 [2] 6f 83 [2] 28 92 [2] 66 9e [2] 6a 94 [2] 7d 9f [2] 66 d1 [2] 5b }

  condition:
    any of them
}