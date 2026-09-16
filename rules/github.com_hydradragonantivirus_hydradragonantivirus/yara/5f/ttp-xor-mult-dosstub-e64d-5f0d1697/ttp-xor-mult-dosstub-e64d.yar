rule TTP_XOR_MULT_DOSStub_e64d {
  strings:
    $key_e64d = { b2 25 [2] c6 3d [2] 81 3f [2] c6 2e [2] 88 22 [2] 84 28 [2] 93 23 [2] 88 6d [2] b5 }

  condition:
    any of them
}