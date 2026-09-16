rule TTP_XOR_MULT_DOSStub_2740 {
  strings:
    $key_2740 = { 73 28 [2] 07 30 [2] 40 32 [2] 07 23 [2] 49 2f [2] 45 25 [2] 52 2e [2] 49 60 [2] 74 }

  condition:
    any of them
}