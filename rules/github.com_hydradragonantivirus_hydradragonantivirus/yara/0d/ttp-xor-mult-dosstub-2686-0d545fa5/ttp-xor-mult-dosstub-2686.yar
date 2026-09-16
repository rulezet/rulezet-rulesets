rule TTP_XOR_MULT_DOSStub_2686 {
  strings:
    $key_2686 = { 72 ee [2] 06 f6 [2] 41 f4 [2] 06 e5 [2] 48 e9 [2] 44 e3 [2] 53 e8 [2] 48 a6 [2] 75 }

  condition:
    any of them
}