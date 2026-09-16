rule TTP_XOR_MULT_DOSStub_0eb8 {
  strings:
    $key_0eb8 = { 5a d0 [2] 2e c8 [2] 69 ca [2] 2e db [2] 60 d7 [2] 6c dd [2] 7b d6 [2] 60 98 [2] 5d }

  condition:
    any of them
}