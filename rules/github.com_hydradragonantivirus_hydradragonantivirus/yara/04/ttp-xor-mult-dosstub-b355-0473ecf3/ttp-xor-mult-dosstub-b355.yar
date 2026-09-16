rule TTP_XOR_MULT_DOSStub_b355 {
  strings:
    $key_b355 = { e7 3d [2] 93 25 [2] d4 27 [2] 93 36 [2] dd 3a [2] d1 30 [2] c6 3b [2] dd 75 [2] e0 }

  condition:
    any of them
}