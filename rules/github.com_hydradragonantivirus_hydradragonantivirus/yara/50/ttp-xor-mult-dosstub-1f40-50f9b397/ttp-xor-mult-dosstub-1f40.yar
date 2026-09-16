rule TTP_XOR_MULT_DOSStub_1f40 {
  strings:
    $key_1f40 = { 4b 28 [2] 3f 30 [2] 78 32 [2] 3f 23 [2] 71 2f [2] 7d 25 [2] 6a 2e [2] 71 60 [2] 4c }

  condition:
    any of them
}