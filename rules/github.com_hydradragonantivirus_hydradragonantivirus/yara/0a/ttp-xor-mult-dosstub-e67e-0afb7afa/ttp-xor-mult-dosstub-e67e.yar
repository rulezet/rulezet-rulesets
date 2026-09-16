rule TTP_XOR_MULT_DOSStub_e67e {
  strings:
    $key_e67e = { b2 16 [2] c6 0e [2] 81 0c [2] c6 1d [2] 88 11 [2] 84 1b [2] 93 10 [2] 88 5e [2] b5 }

  condition:
    any of them
}