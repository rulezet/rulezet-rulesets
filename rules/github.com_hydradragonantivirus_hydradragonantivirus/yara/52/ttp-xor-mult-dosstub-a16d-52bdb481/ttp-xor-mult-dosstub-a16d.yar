rule TTP_XOR_MULT_DOSStub_a16d {
  strings:
    $key_a16d = { f5 05 [2] 81 1d [2] c6 1f [2] 81 0e [2] cf 02 [2] c3 08 [2] d4 03 [2] cf 4d [2] f2 }

  condition:
    any of them
}