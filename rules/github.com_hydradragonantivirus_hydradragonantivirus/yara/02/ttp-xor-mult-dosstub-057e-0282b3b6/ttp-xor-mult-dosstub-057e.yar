rule TTP_XOR_MULT_DOSStub_057e {
  strings:
    $key_057e = { 51 16 [2] 25 0e [2] 62 0c [2] 25 1d [2] 6b 11 [2] 67 1b [2] 70 10 [2] 6b 5e [2] 56 }

  condition:
    any of them
}