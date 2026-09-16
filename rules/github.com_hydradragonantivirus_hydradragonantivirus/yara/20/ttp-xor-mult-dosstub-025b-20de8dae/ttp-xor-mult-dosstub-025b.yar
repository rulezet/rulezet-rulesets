rule TTP_XOR_MULT_DOSStub_025b {
  strings:
    $key_025b = { 56 33 [2] 22 2b [2] 65 29 [2] 22 38 [2] 6c 34 [2] 60 3e [2] 77 35 [2] 6c 7b [2] 51 }

  condition:
    any of them
}