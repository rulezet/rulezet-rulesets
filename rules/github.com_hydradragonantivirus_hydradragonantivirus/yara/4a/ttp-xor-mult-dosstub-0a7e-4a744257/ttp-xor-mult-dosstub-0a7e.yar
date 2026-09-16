rule TTP_XOR_MULT_DOSStub_0a7e {
  strings:
    $key_0a7e = { 5e 16 [2] 2a 0e [2] 6d 0c [2] 2a 1d [2] 64 11 [2] 68 1b [2] 7f 10 [2] 64 5e [2] 59 }

  condition:
    any of them
}