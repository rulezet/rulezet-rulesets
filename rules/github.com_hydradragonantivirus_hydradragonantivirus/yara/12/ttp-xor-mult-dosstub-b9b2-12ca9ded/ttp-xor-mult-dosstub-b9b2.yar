rule TTP_XOR_MULT_DOSStub_b9b2 {
  strings:
    $key_b9b2 = { ed da [2] 99 c2 [2] de c0 [2] 99 d1 [2] d7 dd [2] db d7 [2] cc dc [2] d7 92 [2] ea }

  condition:
    any of them
}