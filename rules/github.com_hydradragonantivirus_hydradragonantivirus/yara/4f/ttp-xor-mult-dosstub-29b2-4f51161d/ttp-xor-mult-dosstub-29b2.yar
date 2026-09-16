rule TTP_XOR_MULT_DOSStub_29b2 {
  strings:
    $key_29b2 = { 7d da [2] 09 c2 [2] 4e c0 [2] 09 d1 [2] 47 dd [2] 4b d7 [2] 5c dc [2] 47 92 [2] 7a }

  condition:
    any of them
}