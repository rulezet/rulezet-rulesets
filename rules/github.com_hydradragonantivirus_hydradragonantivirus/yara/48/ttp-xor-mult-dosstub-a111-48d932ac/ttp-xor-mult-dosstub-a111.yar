rule TTP_XOR_MULT_DOSStub_a111 {
  strings:
    $key_a111 = { f5 79 [2] 81 61 [2] c6 63 [2] 81 72 [2] cf 7e [2] c3 74 [2] d4 7f [2] cf 31 [2] f2 }

  condition:
    any of them
}