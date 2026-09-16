rule TTP_XOR_MULT_DOSStub_5bb2 {
  strings:
    $key_5bb2 = { 0f da [2] 7b c2 [2] 3c c0 [2] 7b d1 [2] 35 dd [2] 39 d7 [2] 2e dc [2] 35 92 [2] 08 }

  condition:
    any of them
}