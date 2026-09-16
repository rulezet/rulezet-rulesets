rule TTP_XOR_MULT_DOSStub_2ef1 {
  strings:
    $key_2ef1 = { 7a 99 [2] 0e 81 [2] 49 83 [2] 0e 92 [2] 40 9e [2] 4c 94 [2] 5b 9f [2] 40 d1 [2] 7d }

  condition:
    any of them
}