rule TTP_XOR_MULT_DOSStub_851d {
  strings:
    $key_851d = { d1 75 [2] a5 6d [2] e2 6f [2] a5 7e [2] eb 72 [2] e7 78 [2] f0 73 [2] eb 3d [2] d6 }

  condition:
    any of them
}