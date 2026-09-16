rule TTP_XOR_MULT_DOSStub_a1e0 {
  strings:
    $key_a1e0 = { f5 88 [2] 81 90 [2] c6 92 [2] 81 83 [2] cf 8f [2] c3 85 [2] d4 8e [2] cf c0 [2] f2 }

  condition:
    any of them
}