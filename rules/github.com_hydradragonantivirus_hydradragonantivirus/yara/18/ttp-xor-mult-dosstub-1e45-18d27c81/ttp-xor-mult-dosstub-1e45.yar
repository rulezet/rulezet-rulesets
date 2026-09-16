rule TTP_XOR_MULT_DOSStub_1e45 {
  strings:
    $key_1e45 = { 4a 2d [2] 3e 35 [2] 79 37 [2] 3e 26 [2] 70 2a [2] 7c 20 [2] 6b 2b [2] 70 65 [2] 4d }

  condition:
    any of them
}