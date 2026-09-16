rule TTP_XOR_MULT_DOSStub_7c1e {
  strings:
    $key_7c1e = { 28 76 [2] 5c 6e [2] 1b 6c [2] 5c 7d [2] 12 71 [2] 1e 7b [2] 09 70 [2] 12 3e [2] 2f }

  condition:
    any of them
}