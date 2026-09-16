rule TTP_XOR_MULT_DOSStub_a121 {
  strings:
    $key_a121 = { f5 49 [2] 81 51 [2] c6 53 [2] 81 42 [2] cf 4e [2] c3 44 [2] d4 4f [2] cf 01 [2] f2 }

  condition:
    any of them
}