rule TTP_XOR_MULT_DOSStub_5d7e {
  strings:
    $key_5d7e = { 09 16 [2] 7d 0e [2] 3a 0c [2] 7d 1d [2] 33 11 [2] 3f 1b [2] 28 10 [2] 33 5e [2] 0e }

  condition:
    any of them
}