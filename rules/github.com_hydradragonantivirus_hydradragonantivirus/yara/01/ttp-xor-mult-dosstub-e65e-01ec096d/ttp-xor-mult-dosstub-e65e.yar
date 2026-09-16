rule TTP_XOR_MULT_DOSStub_e65e {
  strings:
    $key_e65e = { b2 36 [2] c6 2e [2] 81 2c [2] c6 3d [2] 88 31 [2] 84 3b [2] 93 30 [2] 88 7e [2] b5 }

  condition:
    any of them
}