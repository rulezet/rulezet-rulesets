rule TTP_XOR_MULT_DOSStub_a41d {
  strings:
    $key_a41d = { f0 75 [2] 84 6d [2] c3 6f [2] 84 7e [2] ca 72 [2] c6 78 [2] d1 73 [2] ca 3d [2] f7 }

  condition:
    any of them
}