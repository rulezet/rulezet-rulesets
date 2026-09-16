rule TTP_XOR_MULT_DOSStub_1e15 {
  strings:
    $key_1e15 = { 4a 7d [2] 3e 65 [2] 79 67 [2] 3e 76 [2] 70 7a [2] 7c 70 [2] 6b 7b [2] 70 35 [2] 4d }

  condition:
    any of them
}