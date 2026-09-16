rule TTP_XOR_MULT_DOSStub_e9b3 {
  strings:
    $key_e9b3 = { bd db [2] c9 c3 [2] 8e c1 [2] c9 d0 [2] 87 dc [2] 8b d6 [2] 9c dd [2] 87 93 [2] ba }

  condition:
    any of them
}