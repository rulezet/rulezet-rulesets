rule TTP_XOR_MULT_DOSStub_c6e5 {
  strings:
    $key_c6e5 = { 92 8d [2] e6 95 [2] a1 97 [2] e6 86 [2] a8 8a [2] a4 80 [2] b3 8b [2] a8 c5 [2] 95 }

  condition:
    any of them
}