rule TTP_XOR_MULT_DOSStub_b053 {
  strings:
    $key_b053 = { e4 3b [2] 90 23 [2] d7 21 [2] 90 30 [2] de 3c [2] d2 36 [2] c5 3d [2] de 73 [2] e3 }

  condition:
    any of them
}