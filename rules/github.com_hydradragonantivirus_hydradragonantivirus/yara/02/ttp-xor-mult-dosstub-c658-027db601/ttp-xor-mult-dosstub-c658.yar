rule TTP_XOR_MULT_DOSStub_c658 {
  strings:
    $key_c658 = { 92 30 [2] e6 28 [2] a1 2a [2] e6 3b [2] a8 37 [2] a4 3d [2] b3 36 [2] a8 78 [2] 95 }

  condition:
    any of them
}