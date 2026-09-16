rule TTP_XOR_MULT_DOSStub_4c7e {
  strings:
    $key_4c7e = { 18 16 [2] 6c 0e [2] 2b 0c [2] 6c 1d [2] 22 11 [2] 2e 1b [2] 39 10 [2] 22 5e [2] 1f }

  condition:
    any of them
}