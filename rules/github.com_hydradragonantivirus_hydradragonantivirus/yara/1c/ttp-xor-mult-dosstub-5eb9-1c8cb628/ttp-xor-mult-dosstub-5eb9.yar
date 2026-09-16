rule TTP_XOR_MULT_DOSStub_5eb9 {
  strings:
    $key_5eb9 = { 0a d1 [2] 7e c9 [2] 39 cb [2] 7e da [2] 30 d6 [2] 3c dc [2] 2b d7 [2] 30 99 [2] 0d }

  condition:
    any of them
}