rule TTP_XOR_MULT_DOSStub_2a7e {
  strings:
    $key_2a7e = { 7e 16 [2] 0a 0e [2] 4d 0c [2] 0a 1d [2] 44 11 [2] 48 1b [2] 5f 10 [2] 44 5e [2] 79 }

  condition:
    any of them
}