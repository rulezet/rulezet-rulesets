rule TTP_XOR_MULT_DOSStub_1e08 {
  strings:
    $key_1e08 = { 4a 60 [2] 3e 78 [2] 79 7a [2] 3e 6b [2] 70 67 [2] 7c 6d [2] 6b 66 [2] 70 28 [2] 4d }

  condition:
    any of them
}