rule TTP_XOR_MULT_DOSStub_1ee4 {
  strings:
    $key_1ee4 = { 4a 8c [2] 3e 94 [2] 79 96 [2] 3e 87 [2] 70 8b [2] 7c 81 [2] 6b 8a [2] 70 c4 [2] 4d }

  condition:
    any of them
}