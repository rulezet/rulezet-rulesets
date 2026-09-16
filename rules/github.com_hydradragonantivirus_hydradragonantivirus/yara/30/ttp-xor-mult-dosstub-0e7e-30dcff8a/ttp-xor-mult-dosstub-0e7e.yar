rule TTP_XOR_MULT_DOSStub_0e7e {
  strings:
    $key_0e7e = { 5a 16 [2] 2e 0e [2] 69 0c [2] 2e 1d [2] 60 11 [2] 6c 1b [2] 7b 10 [2] 60 5e [2] 5d }

  condition:
    any of them
}