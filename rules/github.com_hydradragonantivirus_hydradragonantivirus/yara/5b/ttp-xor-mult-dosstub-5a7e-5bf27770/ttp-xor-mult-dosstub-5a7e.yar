rule TTP_XOR_MULT_DOSStub_5a7e {
  strings:
    $key_5a7e = { 0e 16 [2] 7a 0e [2] 3d 0c [2] 7a 1d [2] 34 11 [2] 38 1b [2] 2f 10 [2] 34 5e [2] 09 }

  condition:
    any of them
}