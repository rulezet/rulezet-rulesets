rule TTP_XOR_MULT_DOSStub_7a4e {
  strings:
    $key_7a4e = { 2e 26 [2] 5a 3e [2] 1d 3c [2] 5a 2d [2] 14 21 [2] 18 2b [2] 0f 20 [2] 14 6e [2] 29 }

  condition:
    any of them
}