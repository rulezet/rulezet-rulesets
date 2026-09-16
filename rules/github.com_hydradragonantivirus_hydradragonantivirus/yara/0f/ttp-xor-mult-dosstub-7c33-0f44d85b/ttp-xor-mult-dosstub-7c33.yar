rule TTP_XOR_MULT_DOSStub_7c33 {
  strings:
    $key_7c33 = { 28 5b [2] 5c 43 [2] 1b 41 [2] 5c 50 [2] 12 5c [2] 1e 56 [2] 09 5d [2] 12 13 [2] 2f }

  condition:
    any of them
}