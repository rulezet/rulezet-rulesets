rule TTP_XOR_MULT_DOSStub_a13d {
  strings:
    $key_a13d = { f5 55 [2] 81 4d [2] c6 4f [2] 81 5e [2] cf 52 [2] c3 58 [2] d4 53 [2] cf 1d [2] f2 }

  condition:
    any of them
}