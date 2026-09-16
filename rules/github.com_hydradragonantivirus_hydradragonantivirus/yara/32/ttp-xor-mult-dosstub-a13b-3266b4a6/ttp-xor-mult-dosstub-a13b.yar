rule TTP_XOR_MULT_DOSStub_a13b {
  strings:
    $key_a13b = { f5 53 [2] 81 4b [2] c6 49 [2] 81 58 [2] cf 54 [2] c3 5e [2] d4 55 [2] cf 1b [2] f2 }

  condition:
    any of them
}