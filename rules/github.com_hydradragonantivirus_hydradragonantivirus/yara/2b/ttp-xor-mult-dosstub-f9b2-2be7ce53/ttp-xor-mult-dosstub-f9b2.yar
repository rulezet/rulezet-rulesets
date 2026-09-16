rule TTP_XOR_MULT_DOSStub_f9b2 {
  strings:
    $key_f9b2 = { ad da [2] d9 c2 [2] 9e c0 [2] d9 d1 [2] 97 dd [2] 9b d7 [2] 8c dc [2] 97 92 [2] aa }

  condition:
    any of them
}