rule TTP_XOR_MULT_DOSStub_3eb9 {
  strings:
    $key_3eb9 = { 6a d1 [2] 1e c9 [2] 59 cb [2] 1e da [2] 50 d6 [2] 5c dc [2] 4b d7 [2] 50 99 [2] 6d }

  condition:
    any of them
}