rule TTP_XOR_MULT_DOSStub_a707 {
  strings:
    $key_a707 = { f3 6f [2] 87 77 [2] c0 75 [2] 87 64 [2] c9 68 [2] c5 62 [2] d2 69 [2] c9 27 [2] f4 }

  condition:
    any of them
}