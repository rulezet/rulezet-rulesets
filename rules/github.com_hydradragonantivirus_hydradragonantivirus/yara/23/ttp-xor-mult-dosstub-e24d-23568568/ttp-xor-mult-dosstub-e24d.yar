rule TTP_XOR_MULT_DOSStub_e24d {
  strings:
    $key_e24d = { b6 25 [2] c2 3d [2] 85 3f [2] c2 2e [2] 8c 22 [2] 80 28 [2] 97 23 [2] 8c 6d [2] b1 }

  condition:
    any of them
}