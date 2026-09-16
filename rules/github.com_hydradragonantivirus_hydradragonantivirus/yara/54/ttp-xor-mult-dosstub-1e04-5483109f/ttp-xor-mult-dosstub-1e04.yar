rule TTP_XOR_MULT_DOSStub_1e04 {
  strings:
    $key_1e04 = { 4a 6c [2] 3e 74 [2] 79 76 [2] 3e 67 [2] 70 6b [2] 7c 61 [2] 6b 6a [2] 70 24 [2] 4d }

  condition:
    any of them
}