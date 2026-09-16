rule TTP_XOR_MULT_DOSStub_b63b {
  strings:
    $key_b63b = { e2 53 [2] 96 4b [2] d1 49 [2] 96 58 [2] d8 54 [2] d4 5e [2] c3 55 [2] d8 1b [2] e5 }

  condition:
    any of them
}