rule TTP_XOR_MULT_DOSStub_1e78 {
  strings:
    $key_1e78 = { 4a 10 [2] 3e 08 [2] 79 0a [2] 3e 1b [2] 70 17 [2] 7c 1d [2] 6b 16 [2] 70 58 [2] 4d }

  condition:
    any of them
}