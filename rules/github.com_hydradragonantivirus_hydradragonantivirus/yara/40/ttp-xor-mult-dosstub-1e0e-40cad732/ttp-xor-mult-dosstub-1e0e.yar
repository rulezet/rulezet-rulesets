rule TTP_XOR_MULT_DOSStub_1e0e {
  strings:
    $key_1e0e = { 4a 66 [2] 3e 7e [2] 79 7c [2] 3e 6d [2] 70 61 [2] 7c 6b [2] 6b 60 [2] 70 2e [2] 4d }

  condition:
    any of them
}