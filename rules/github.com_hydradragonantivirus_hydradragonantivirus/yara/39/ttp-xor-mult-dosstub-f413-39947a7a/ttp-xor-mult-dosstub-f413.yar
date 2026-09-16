rule TTP_XOR_MULT_DOSStub_f413 {
  strings:
    $key_f413 = { a0 7b [2] d4 63 [2] 93 61 [2] d4 70 [2] 9a 7c [2] 96 76 [2] 81 7d [2] 9a 33 [2] a7 }

  condition:
    any of them
}