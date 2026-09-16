rule TTP_XOR_MULT_DOSStub_f143 {
  strings:
    $key_f143 = { a5 2b [2] d1 33 [2] 96 31 [2] d1 20 [2] 9f 2c [2] 93 26 [2] 84 2d [2] 9f 63 [2] a2 }

  condition:
    any of them
}