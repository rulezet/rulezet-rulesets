rule TTP_XOR_MULT_DOSStub_b74d {
  strings:
    $key_b74d = { e3 25 [2] 97 3d [2] d0 3f [2] 97 2e [2] d9 22 [2] d5 28 [2] c2 23 [2] d9 6d [2] e4 }

  condition:
    any of them
}