rule TTP_XOR_MULT_DOSStub_e677 {
  strings:
    $key_e677 = { b2 1f [2] c6 07 [2] 81 05 [2] c6 14 [2] 88 18 [2] 84 12 [2] 93 19 [2] 88 57 [2] b5 }

  condition:
    any of them
}