rule TTP_XOR_MULT_DOSStub_0eb9 {
  strings:
    $key_0eb9 = { 5a d1 [2] 2e c9 [2] 69 cb [2] 2e da [2] 60 d6 [2] 6c dc [2] 7b d7 [2] 60 99 [2] 5d }

  condition:
    any of them
}