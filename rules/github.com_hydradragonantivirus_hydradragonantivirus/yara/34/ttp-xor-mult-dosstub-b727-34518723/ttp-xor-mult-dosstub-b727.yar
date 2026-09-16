rule TTP_XOR_MULT_DOSStub_b727 {
  strings:
    $key_b727 = { e3 4f [2] 97 57 [2] d0 55 [2] 97 44 [2] d9 48 [2] d5 42 [2] c2 49 [2] d9 07 [2] e4 }

  condition:
    any of them
}