rule TTP_XOR_MULT_DOSStub_b758 {
  strings:
    $key_b758 = { e3 30 [2] 97 28 [2] d0 2a [2] 97 3b [2] d9 37 [2] d5 3d [2] c2 36 [2] d9 78 [2] e4 }

  condition:
    any of them
}