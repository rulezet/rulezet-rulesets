rule TTP_XOR_MULT_DOSStub_59b2 {
  strings:
    $key_59b2 = { 0d da [2] 79 c2 [2] 3e c0 [2] 79 d1 [2] 37 dd [2] 3b d7 [2] 2c dc [2] 37 92 [2] 0a }

  condition:
    any of them
}