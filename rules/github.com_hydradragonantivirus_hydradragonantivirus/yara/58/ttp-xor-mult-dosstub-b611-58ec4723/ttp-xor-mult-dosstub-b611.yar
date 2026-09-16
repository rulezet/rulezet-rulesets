rule TTP_XOR_MULT_DOSStub_b611 {
  strings:
    $key_b611 = { e2 79 [2] 96 61 [2] d1 63 [2] 96 72 [2] d8 7e [2] d4 74 [2] c3 7f [2] d8 31 [2] e5 }

  condition:
    any of them
}