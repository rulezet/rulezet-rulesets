rule TTP_XOR_MULT_DOSStub_e02d {
  strings:
    $key_e02d = { b4 45 [2] c0 5d [2] 87 5f [2] c0 4e [2] 8e 42 [2] 82 48 [2] 95 43 [2] 8e 0d [2] b3 }

  condition:
    any of them
}