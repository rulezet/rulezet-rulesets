rule TTP_XOR_MULT_DOSStub_e14e {
  strings:
    $key_e14e = { b5 26 [2] c1 3e [2] 86 3c [2] c1 2d [2] 8f 21 [2] 83 2b [2] 94 20 [2] 8f 6e [2] b2 }

  condition:
    any of them
}