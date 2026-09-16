rule TTP_XOR_MULT_DOSStub_154e {
  strings:
    $key_154e = { 41 26 [2] 35 3e [2] 72 3c [2] 35 2d [2] 7b 21 [2] 77 2b [2] 60 20 [2] 7b 6e [2] 46 }

  condition:
    any of them
}