rule TTP_XOR_MULT_DOSStub_b631 {
  strings:
    $key_b631 = { e2 59 [2] 96 41 [2] d1 43 [2] 96 52 [2] d8 5e [2] d4 54 [2] c3 5f [2] d8 11 [2] e5 }

  condition:
    any of them
}