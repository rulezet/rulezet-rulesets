rule TTP_XOR_MULT_DOSStub_c6f4 {
  strings:
    $key_c6f4 = { 92 9c [2] e6 84 [2] a1 86 [2] e6 97 [2] a8 9b [2] a4 91 [2] b3 9a [2] a8 d4 [2] 95 }

  condition:
    any of them
}