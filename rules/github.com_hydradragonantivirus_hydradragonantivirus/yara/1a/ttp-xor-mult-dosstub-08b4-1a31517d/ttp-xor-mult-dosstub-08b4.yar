rule TTP_XOR_MULT_DOSStub_08b4 {
  strings:
    $key_08b4 = { 5c dc [2] 28 c4 [2] 6f c6 [2] 28 d7 [2] 66 db [2] 6a d1 [2] 7d da [2] 66 94 [2] 5b }

  condition:
    any of them
}