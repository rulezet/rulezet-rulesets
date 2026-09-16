rule TTP_XOR_MULT_DOSStub_09a8 {
  strings:
    $key_09a8 = { 5d c0 [2] 29 d8 [2] 6e da [2] 29 cb [2] 67 c7 [2] 6b cd [2] 7c c6 [2] 67 88 [2] 5a }

  condition:
    any of them
}