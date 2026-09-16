rule TTP_XOR_MULT_DOSStub_247e {
  strings:
    $key_247e = { 70 16 [2] 04 0e [2] 43 0c [2] 04 1d [2] 4a 11 [2] 46 1b [2] 51 10 [2] 4a 5e [2] 77 }

  condition:
    any of them
}