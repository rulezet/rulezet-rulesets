rule TTP_XOR_MULT_DOSStub_717e {
  strings:
    $key_717e = { 25 16 [2] 51 0e [2] 16 0c [2] 51 1d [2] 1f 11 [2] 13 1b [2] 04 10 [2] 1f 5e [2] 22 }

  condition:
    any of them
}