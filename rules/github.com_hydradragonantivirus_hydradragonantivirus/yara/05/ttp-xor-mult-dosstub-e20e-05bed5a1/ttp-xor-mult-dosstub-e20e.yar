rule TTP_XOR_MULT_DOSStub_e20e {
  strings:
    $key_e20e = { b6 66 [2] c2 7e [2] 85 7c [2] c2 6d [2] 8c 61 [2] 80 6b [2] 97 60 [2] 8c 2e [2] b1 }

  condition:
    any of them
}