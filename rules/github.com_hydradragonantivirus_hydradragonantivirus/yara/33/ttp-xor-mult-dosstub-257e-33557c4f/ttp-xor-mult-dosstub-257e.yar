rule TTP_XOR_MULT_DOSStub_257e {
  strings:
    $key_257e = { 71 16 [2] 05 0e [2] 42 0c [2] 05 1d [2] 4b 11 [2] 47 1b [2] 50 10 [2] 4b 5e [2] 76 }

  condition:
    any of them
}