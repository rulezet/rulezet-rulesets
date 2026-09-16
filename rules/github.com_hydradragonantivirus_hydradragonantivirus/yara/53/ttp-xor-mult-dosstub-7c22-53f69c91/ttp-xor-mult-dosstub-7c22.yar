rule TTP_XOR_MULT_DOSStub_7c22 {
  strings:
    $key_7c22 = { 28 4a [2] 5c 52 [2] 1b 50 [2] 5c 41 [2] 12 4d [2] 1e 47 [2] 09 4c [2] 12 02 [2] 2f }

  condition:
    any of them
}