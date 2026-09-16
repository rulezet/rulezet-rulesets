rule TTP_XOR_MULT_DOSStub_237e {
  strings:
    $key_237e = { 77 16 [2] 03 0e [2] 44 0c [2] 03 1d [2] 4d 11 [2] 41 1b [2] 56 10 [2] 4d 5e [2] 70 }

  condition:
    any of them
}