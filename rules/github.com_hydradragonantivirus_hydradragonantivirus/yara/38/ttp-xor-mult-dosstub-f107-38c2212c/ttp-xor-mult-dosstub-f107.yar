rule TTP_XOR_MULT_DOSStub_f107 {
  strings:
    $key_f107 = { a5 6f [2] d1 77 [2] 96 75 [2] d1 64 [2] 9f 68 [2] 93 62 [2] 84 69 [2] 9f 27 [2] a2 }

  condition:
    any of them
}