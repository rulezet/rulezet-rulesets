rule TTP_XOR_MULT_DOSStub_f422 {
  strings:
    $key_f422 = { a0 4a [2] d4 52 [2] 93 50 [2] d4 41 [2] 9a 4d [2] 96 47 [2] 81 4c [2] 9a 02 [2] a7 }

  condition:
    any of them
}