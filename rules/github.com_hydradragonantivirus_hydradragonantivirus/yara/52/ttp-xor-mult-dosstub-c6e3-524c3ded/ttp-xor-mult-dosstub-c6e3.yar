rule TTP_XOR_MULT_DOSStub_c6e3 {
  strings:
    $key_c6e3 = { 92 8b [2] e6 93 [2] a1 91 [2] e6 80 [2] a8 8c [2] a4 86 [2] b3 8d [2] a8 c3 [2] 95 }

  condition:
    any of them
}