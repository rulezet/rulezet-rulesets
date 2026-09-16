rule TTP_XOR_MULT_DOSStub_2e7e {
  strings:
    $key_2e7e = { 7a 16 [2] 0e 0e [2] 49 0c [2] 0e 1d [2] 40 11 [2] 4c 1b [2] 5b 10 [2] 40 5e [2] 7d }

  condition:
    any of them
}