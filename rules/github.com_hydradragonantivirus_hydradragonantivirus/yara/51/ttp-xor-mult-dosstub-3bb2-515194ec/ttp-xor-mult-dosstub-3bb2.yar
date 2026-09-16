rule TTP_XOR_MULT_DOSStub_3bb2 {
  strings:
    $key_3bb2 = { 6f da [2] 1b c2 [2] 5c c0 [2] 1b d1 [2] 55 dd [2] 59 d7 [2] 4e dc [2] 55 92 [2] 68 }

  condition:
    any of them
}