rule TTP_XOR_MULT_DOSStub_2746 {
  strings:
    $key_2746 = { 73 2e [2] 07 36 [2] 40 34 [2] 07 25 [2] 49 29 [2] 45 23 [2] 52 28 [2] 49 66 [2] 74 }

  condition:
    any of them
}