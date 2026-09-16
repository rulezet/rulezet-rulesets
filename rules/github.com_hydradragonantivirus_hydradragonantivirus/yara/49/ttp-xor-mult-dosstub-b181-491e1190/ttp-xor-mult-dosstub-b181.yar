rule TTP_XOR_MULT_DOSStub_b181 {
  strings:
    $key_b181 = { e5 e9 [2] 91 f1 [2] d6 f3 [2] 91 e2 [2] df ee [2] d3 e4 [2] c4 ef [2] df a1 [2] e2 }

  condition:
    any of them
}