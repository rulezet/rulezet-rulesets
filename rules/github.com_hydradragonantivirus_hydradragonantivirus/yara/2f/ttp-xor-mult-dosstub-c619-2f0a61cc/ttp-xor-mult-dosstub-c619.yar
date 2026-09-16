rule TTP_XOR_MULT_DOSStub_c619 {
  strings:
    $key_c619 = { 92 71 [2] e6 69 [2] a1 6b [2] e6 7a [2] a8 76 [2] a4 7c [2] b3 77 [2] a8 39 [2] 95 }

  condition:
    any of them
}