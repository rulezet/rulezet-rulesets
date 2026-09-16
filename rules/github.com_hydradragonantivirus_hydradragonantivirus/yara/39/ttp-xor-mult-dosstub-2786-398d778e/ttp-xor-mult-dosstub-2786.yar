rule TTP_XOR_MULT_DOSStub_2786 {
  strings:
    $key_2786 = { 73 ee [2] 07 f6 [2] 40 f4 [2] 07 e5 [2] 49 e9 [2] 45 e3 [2] 52 e8 [2] 49 a6 [2] 74 }

  condition:
    any of them
}