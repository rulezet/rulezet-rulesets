rule TTP_XOR_MULT_DOSStub_b61d {
  strings:
    $key_b61d = { e2 75 [2] 96 6d [2] d1 6f [2] 96 7e [2] d8 72 [2] d4 78 [2] c3 73 [2] d8 3d [2] e5 }

  condition:
    any of them
}