rule TTP_XOR_MULT_DOSStub_3e1e {
  strings:
    $key_3e1e = { 6a 76 [2] 1e 6e [2] 59 6c [2] 1e 7d [2] 50 71 [2] 5c 7b [2] 4b 70 [2] 50 3e [2] 6d }

  condition:
    any of them
}