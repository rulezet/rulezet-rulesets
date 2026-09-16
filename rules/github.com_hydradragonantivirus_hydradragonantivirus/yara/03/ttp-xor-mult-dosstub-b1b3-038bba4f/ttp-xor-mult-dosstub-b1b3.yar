rule TTP_XOR_MULT_DOSStub_b1b3 {
  strings:
    $key_b1b3 = { e5 db [2] 91 c3 [2] d6 c1 [2] 91 d0 [2] df dc [2] d3 d6 [2] c4 dd [2] df 93 [2] e2 }

  condition:
    any of them
}