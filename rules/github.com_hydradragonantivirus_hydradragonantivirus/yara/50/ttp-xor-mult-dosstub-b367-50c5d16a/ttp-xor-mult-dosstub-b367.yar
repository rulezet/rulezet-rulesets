rule TTP_XOR_MULT_DOSStub_b367 {
  strings:
    $key_b367 = { e7 0f [2] 93 17 [2] d4 15 [2] 93 04 [2] dd 08 [2] d1 02 [2] c6 09 [2] dd 47 [2] e0 }

  condition:
    any of them
}