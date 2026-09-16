rule TTP_XOR_MULT_DOSStub_1e54 {
  strings:
    $key_1e54 = { 4a 3c [2] 3e 24 [2] 79 26 [2] 3e 37 [2] 70 3b [2] 7c 31 [2] 6b 3a [2] 70 74 [2] 4d }

  condition:
    any of them
}