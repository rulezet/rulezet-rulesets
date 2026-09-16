rule TTP_XOR_MULT_DOSStub_e17e {
  strings:
    $key_e17e = { b5 16 [2] c1 0e [2] 86 0c [2] c1 1d [2] 8f 11 [2] 83 1b [2] 94 10 [2] 8f 5e [2] b2 }

  condition:
    any of them
}