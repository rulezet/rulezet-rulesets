rule TTP_XOR_MULT_DOSStub_c6f9 {
  strings:
    $key_c6f9 = { 92 91 [2] e6 89 [2] a1 8b [2] e6 9a [2] a8 96 [2] a4 9c [2] b3 97 [2] a8 d9 [2] 95 }

  condition:
    any of them
}