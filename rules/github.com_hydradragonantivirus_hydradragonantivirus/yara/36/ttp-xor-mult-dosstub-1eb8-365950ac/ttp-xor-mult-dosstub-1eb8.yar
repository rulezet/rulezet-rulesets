rule TTP_XOR_MULT_DOSStub_1eb8 {
  strings:
    $key_1eb8 = { 4a d0 [2] 3e c8 [2] 79 ca [2] 3e db [2] 70 d7 [2] 7c dd [2] 6b d6 [2] 70 98 [2] 4d }

  condition:
    any of them
}