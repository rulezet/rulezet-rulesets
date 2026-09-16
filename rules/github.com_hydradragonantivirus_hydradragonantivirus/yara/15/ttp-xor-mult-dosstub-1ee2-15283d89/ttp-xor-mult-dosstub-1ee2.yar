rule TTP_XOR_MULT_DOSStub_1ee2 {
  strings:
    $key_1ee2 = { 4a 8a [2] 3e 92 [2] 79 90 [2] 3e 81 [2] 70 8d [2] 7c 87 [2] 6b 8c [2] 70 c2 [2] 4d }

  condition:
    any of them
}