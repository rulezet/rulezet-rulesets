rule TTP_XOR_MULT_DOSStub_1f16 {
  strings:
    $key_1f16 = { 4b 7e [2] 3f 66 [2] 78 64 [2] 3f 75 [2] 71 79 [2] 7d 73 [2] 6a 78 [2] 71 36 [2] 4c }

  condition:
    any of them
}