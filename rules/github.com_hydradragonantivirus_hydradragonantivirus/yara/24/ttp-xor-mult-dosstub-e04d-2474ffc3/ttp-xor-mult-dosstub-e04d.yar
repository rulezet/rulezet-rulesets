rule TTP_XOR_MULT_DOSStub_e04d {
  strings:
    $key_e04d = { b4 25 [2] c0 3d [2] 87 3f [2] c0 2e [2] 8e 22 [2] 82 28 [2] 95 23 [2] 8e 6d [2] b3 }

  condition:
    any of them
}