rule TTP_XOR_MULT_DOSStub_153e {
  strings:
    $key_153e = { 41 56 [2] 35 4e [2] 72 4c [2] 35 5d [2] 7b 51 [2] 77 5b [2] 60 50 [2] 7b 1e [2] 46 }

  condition:
    any of them
}