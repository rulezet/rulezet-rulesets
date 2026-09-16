rule TTP_XOR_MULT_DOSStub_2bb2 {
  strings:
    $key_2bb2 = { 7f da [2] 0b c2 [2] 4c c0 [2] 0b d1 [2] 45 dd [2] 49 d7 [2] 5e dc [2] 45 92 [2] 78 }

  condition:
    any of them
}