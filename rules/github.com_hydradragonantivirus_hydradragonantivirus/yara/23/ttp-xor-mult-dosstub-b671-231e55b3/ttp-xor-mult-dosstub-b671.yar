rule TTP_XOR_MULT_DOSStub_b671 {
  strings:
    $key_b671 = { e2 19 [2] 96 01 [2] d1 03 [2] 96 12 [2] d8 1e [2] d4 14 [2] c3 1f [2] d8 51 [2] e5 }

  condition:
    any of them
}