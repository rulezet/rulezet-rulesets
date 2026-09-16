rule TTP_XOR_MULT_DOSStub_49b2 {
  strings:
    $key_49b2 = { 1d da [2] 69 c2 [2] 2e c0 [2] 69 d1 [2] 27 dd [2] 2b d7 [2] 3c dc [2] 27 92 [2] 1a }

  condition:
    any of them
}