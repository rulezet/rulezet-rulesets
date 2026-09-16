rule TTP_XOR_MULT_DOSStub_f127 {
  strings:
    $key_f127 = { a5 4f [2] d1 57 [2] 96 55 [2] d1 44 [2] 9f 48 [2] 93 42 [2] 84 49 [2] 9f 07 [2] a2 }

  condition:
    any of them
}