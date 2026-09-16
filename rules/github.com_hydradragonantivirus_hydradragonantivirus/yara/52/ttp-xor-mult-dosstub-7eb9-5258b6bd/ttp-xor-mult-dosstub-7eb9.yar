rule TTP_XOR_MULT_DOSStub_7eb9 {
  strings:
    $key_7eb9 = { 2a d1 [2] 5e c9 [2] 19 cb [2] 5e da [2] 10 d6 [2] 1c dc [2] 0b d7 [2] 10 99 [2] 2d }

  condition:
    any of them
}