rule TTP_XOR_MULT_DOSStub_c61f {
  strings:
    $key_c61f = { 92 77 [2] e6 6f [2] a1 6d [2] e6 7c [2] a8 70 [2] a4 7a [2] b3 71 [2] a8 3f [2] 95 }

  condition:
    any of them
}