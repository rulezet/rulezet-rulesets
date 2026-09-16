rule TTP_XOR_MULT_DOSStub_147e {
  strings:
    $key_147e = { 40 16 [2] 34 0e [2] 73 0c [2] 34 1d [2] 7a 11 [2] 76 1b [2] 61 10 [2] 7a 5e [2] 47 }

  condition:
    any of them
}