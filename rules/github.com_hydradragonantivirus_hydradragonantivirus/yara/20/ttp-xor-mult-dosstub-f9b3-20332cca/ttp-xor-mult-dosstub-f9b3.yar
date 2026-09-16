rule TTP_XOR_MULT_DOSStub_f9b3 {
  strings:
    $key_f9b3 = { ad db [2] d9 c3 [2] 9e c1 [2] d9 d0 [2] 97 dc [2] 9b d6 [2] 8c dd [2] 97 93 [2] aa }

  condition:
    any of them
}