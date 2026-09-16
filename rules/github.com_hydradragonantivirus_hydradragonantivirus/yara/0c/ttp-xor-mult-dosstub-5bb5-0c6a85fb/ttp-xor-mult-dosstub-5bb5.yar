rule TTP_XOR_MULT_DOSStub_5bb5 {
  strings:
    $key_5bb5 = { 0f dd [2] 7b c5 [2] 3c c7 [2] 7b d6 [2] 35 da [2] 39 d0 [2] 2e db [2] 35 95 [2] 08 }

  condition:
    any of them
}