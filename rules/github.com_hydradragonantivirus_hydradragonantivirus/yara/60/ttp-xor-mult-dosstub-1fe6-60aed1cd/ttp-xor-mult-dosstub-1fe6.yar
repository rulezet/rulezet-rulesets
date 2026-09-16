rule TTP_XOR_MULT_DOSStub_1fe6 {
  strings:
    $key_1fe6 = { 4b 8e [2] 3f 96 [2] 78 94 [2] 3f 85 [2] 71 89 [2] 7d 83 [2] 6a 88 [2] 71 c6 [2] 4c }

  condition:
    any of them
}