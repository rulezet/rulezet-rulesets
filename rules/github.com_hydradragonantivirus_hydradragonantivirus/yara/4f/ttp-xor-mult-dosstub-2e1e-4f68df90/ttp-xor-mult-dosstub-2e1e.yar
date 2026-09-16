rule TTP_XOR_MULT_DOSStub_2e1e {
  strings:
    $key_2e1e = { 7a 76 [2] 0e 6e [2] 49 6c [2] 0e 7d [2] 40 71 [2] 4c 7b [2] 5b 70 [2] 40 3e [2] 7d }

  condition:
    any of them
}