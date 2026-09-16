rule TTP_XOR_MULT_DOSStub_e24e {
  strings:
    $key_e24e = { b6 26 [2] c2 3e [2] 85 3c [2] c2 2d [2] 8c 21 [2] 80 2b [2] 97 20 [2] 8c 6e [2] b1 }

  condition:
    any of them
}