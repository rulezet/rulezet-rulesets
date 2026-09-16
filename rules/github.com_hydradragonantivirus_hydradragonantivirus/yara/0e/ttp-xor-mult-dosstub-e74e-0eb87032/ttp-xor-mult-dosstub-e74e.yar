rule TTP_XOR_MULT_DOSStub_e74e {
  strings:
    $key_e74e = { b3 26 [2] c7 3e [2] 80 3c [2] c7 2d [2] 89 21 [2] 85 2b [2] 92 20 [2] 89 6e [2] b4 }

  condition:
    any of them
}