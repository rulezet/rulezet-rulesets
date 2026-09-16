rule TTP_XOR_MULT_DOSStub_460e {
  strings:
    $key_460e = { 12 66 [2] 66 7e [2] 21 7c [2] 66 6d [2] 28 61 [2] 24 6b [2] 33 60 [2] 28 2e [2] 15 }

  condition:
    any of them
}