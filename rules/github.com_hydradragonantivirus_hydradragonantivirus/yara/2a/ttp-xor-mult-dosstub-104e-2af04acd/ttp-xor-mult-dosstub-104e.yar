rule TTP_XOR_MULT_DOSStub_104e {
  strings:
    $key_104e = { 44 26 [2] 30 3e [2] 77 3c [2] 30 2d [2] 7e 21 [2] 72 2b [2] 65 20 [2] 7e 6e [2] 43 }

  condition:
    any of them
}