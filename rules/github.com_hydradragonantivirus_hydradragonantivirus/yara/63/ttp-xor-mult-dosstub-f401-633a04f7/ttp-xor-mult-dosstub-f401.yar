rule TTP_XOR_MULT_DOSStub_f401 {
  strings:
    $key_f401 = { a0 69 [2] d4 71 [2] 93 73 [2] d4 62 [2] 9a 6e [2] 96 64 [2] 81 6f [2] 9a 21 [2] a7 }

  condition:
    any of them
}