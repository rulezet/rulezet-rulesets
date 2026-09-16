rule TTP_XOR_MULT_DOSStub_65d2 {
  strings:
    $key_65d2 = { 31 ba [2] 45 a2 [2] 02 a0 [2] 45 b1 [2] 0b bd [2] 07 b7 [2] 10 bc [2] 0b f2 [2] 36 }

  condition:
    any of them
}