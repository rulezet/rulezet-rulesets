rule TTP_XOR_MULT_DOSStub_6bb5 {
  strings:
    $key_6bb5 = { 3f dd [2] 4b c5 [2] 0c c7 [2] 4b d6 [2] 05 da [2] 09 d0 [2] 1e db [2] 05 95 [2] 38 }

  condition:
    any of them
}