rule TTP_XOR_MULT_DOSStub_65ca {
  strings:
    $key_65ca = { 31 a2 [2] 45 ba [2] 02 b8 [2] 45 a9 [2] 0b a5 [2] 07 af [2] 10 a4 [2] 0b ea [2] 36 }

  condition:
    any of them
}