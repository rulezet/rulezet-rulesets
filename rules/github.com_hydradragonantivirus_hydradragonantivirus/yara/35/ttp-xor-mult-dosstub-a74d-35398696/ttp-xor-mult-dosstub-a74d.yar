rule TTP_XOR_MULT_DOSStub_a74d {
  strings:
    $key_a74d = { f3 25 [2] 87 3d [2] c0 3f [2] 87 2e [2] c9 22 [2] c5 28 [2] d2 23 [2] c9 6d [2] f4 }

  condition:
    any of them
}