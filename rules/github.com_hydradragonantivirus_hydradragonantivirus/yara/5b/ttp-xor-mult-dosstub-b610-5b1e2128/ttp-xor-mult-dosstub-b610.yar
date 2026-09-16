rule TTP_XOR_MULT_DOSStub_b610 {
  strings:
    $key_b610 = { e2 78 [2] 96 60 [2] d1 62 [2] 96 73 [2] d8 7f [2] d4 75 [2] c3 7e [2] d8 30 [2] e5 }

  condition:
    any of them
}