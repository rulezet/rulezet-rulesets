rule TTP_XOR_MULT_DOSStub_a453 {
  strings:
    $key_a453 = { f0 3b [2] 84 23 [2] c3 21 [2] 84 30 [2] ca 3c [2] c6 36 [2] d1 3d [2] ca 73 [2] f7 }

  condition:
    any of them
}