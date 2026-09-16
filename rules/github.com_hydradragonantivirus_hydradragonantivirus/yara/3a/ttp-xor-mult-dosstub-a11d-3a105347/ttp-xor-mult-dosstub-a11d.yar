rule TTP_XOR_MULT_DOSStub_a11d {
  strings:
    $key_a11d = { f5 75 [2] 81 6d [2] c6 6f [2] 81 7e [2] cf 72 [2] c3 78 [2] d4 73 [2] cf 3d [2] f2 }

  condition:
    any of them
}