rule TTP_XOR_MULT_DOSStub_b2b3 {
  strings:
    $key_b2b3 = { e6 db [2] 92 c3 [2] d5 c1 [2] 92 d0 [2] dc dc [2] d0 d6 [2] c7 dd [2] dc 93 [2] e1 }

  condition:
    any of them
}