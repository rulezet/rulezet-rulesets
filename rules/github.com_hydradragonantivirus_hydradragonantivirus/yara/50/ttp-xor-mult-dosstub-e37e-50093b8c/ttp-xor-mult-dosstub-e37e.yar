rule TTP_XOR_MULT_DOSStub_e37e {
  strings:
    $key_e37e = { b7 16 [2] c3 0e [2] 84 0c [2] c3 1d [2] 8d 11 [2] 81 1b [2] 96 10 [2] 8d 5e [2] b0 }

  condition:
    any of them
}