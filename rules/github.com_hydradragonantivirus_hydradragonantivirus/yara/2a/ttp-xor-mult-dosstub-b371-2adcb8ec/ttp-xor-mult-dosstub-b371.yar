rule TTP_XOR_MULT_DOSStub_b371 {
  strings:
    $key_b371 = { e7 19 [2] 93 01 [2] d4 03 [2] 93 12 [2] dd 1e [2] d1 14 [2] c6 1f [2] dd 51 [2] e0 }

  condition:
    any of them
}