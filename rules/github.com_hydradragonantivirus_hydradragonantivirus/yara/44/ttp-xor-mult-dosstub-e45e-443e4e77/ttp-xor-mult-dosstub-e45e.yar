rule TTP_XOR_MULT_DOSStub_e45e {
  strings:
    $key_e45e = { b0 36 [2] c4 2e [2] 83 2c [2] c4 3d [2] 8a 31 [2] 86 3b [2] 91 30 [2] 8a 7e [2] b7 }

  condition:
    any of them
}