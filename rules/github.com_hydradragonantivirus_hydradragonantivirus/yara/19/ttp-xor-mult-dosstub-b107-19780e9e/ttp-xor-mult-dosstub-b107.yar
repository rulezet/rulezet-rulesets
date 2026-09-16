rule TTP_XOR_MULT_DOSStub_b107 {
  strings:
    $key_b107 = { e5 6f [2] 91 77 [2] d6 75 [2] 91 64 [2] df 68 [2] d3 62 [2] c4 69 [2] df 27 [2] e2 }

  condition:
    any of them
}