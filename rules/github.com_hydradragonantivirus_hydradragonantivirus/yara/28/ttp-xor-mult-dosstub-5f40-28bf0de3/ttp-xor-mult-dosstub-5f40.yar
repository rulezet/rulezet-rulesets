rule TTP_XOR_MULT_DOSStub_5f40 {
  strings:
    $key_5f40 = { 0b 28 [2] 7f 30 [2] 38 32 [2] 7f 23 [2] 31 2f [2] 3d 25 [2] 2a 2e [2] 31 60 [2] 0c }

  condition:
    any of them
}