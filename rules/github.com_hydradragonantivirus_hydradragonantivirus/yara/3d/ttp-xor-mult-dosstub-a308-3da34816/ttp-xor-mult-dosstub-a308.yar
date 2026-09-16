rule TTP_XOR_MULT_DOSStub_a308 {
  strings:
    $key_a308 = { f7 60 [2] 83 78 [2] c4 7a [2] 83 6b [2] cd 67 [2] c1 6d [2] d6 66 [2] cd 28 [2] f0 }

  condition:
    any of them
}