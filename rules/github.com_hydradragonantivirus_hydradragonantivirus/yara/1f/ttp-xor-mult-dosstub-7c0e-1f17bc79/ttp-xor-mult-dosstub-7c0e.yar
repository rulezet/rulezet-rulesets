rule TTP_XOR_MULT_DOSStub_7c0e {
  strings:
    $key_7c0e = { 28 66 [2] 5c 7e [2] 1b 7c [2] 5c 6d [2] 12 61 [2] 1e 6b [2] 09 60 [2] 12 2e [2] 2f }

  condition:
    any of them
}