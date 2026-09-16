rule TTP_XOR_MULT_DOSStub_b2b5 {
  strings:
    $key_b2b5 = { e6 dd [2] 92 c5 [2] d5 c7 [2] 92 d6 [2] dc da [2] d0 d0 [2] c7 db [2] dc 95 [2] e1 }

  condition:
    any of them
}