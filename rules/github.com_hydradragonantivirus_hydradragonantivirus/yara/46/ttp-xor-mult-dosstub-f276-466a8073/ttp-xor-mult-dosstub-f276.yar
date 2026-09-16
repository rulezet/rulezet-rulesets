rule TTP_XOR_MULT_DOSStub_f276 {
  strings:
    $key_f276 = { a6 1e [2] d2 06 [2] 95 04 [2] d2 15 [2] 9c 19 [2] 90 13 [2] 87 18 [2] 9c 56 [2] a1 }

  condition:
    any of them
}