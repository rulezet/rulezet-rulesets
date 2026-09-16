rule TTP_XOR_MULT_DOSStub_0e1e {
  strings:
    $key_0e1e = { 5a 76 [2] 2e 6e [2] 69 6c [2] 2e 7d [2] 60 71 [2] 6c 7b [2] 7b 70 [2] 60 3e [2] 5d }

  condition:
    any of them
}