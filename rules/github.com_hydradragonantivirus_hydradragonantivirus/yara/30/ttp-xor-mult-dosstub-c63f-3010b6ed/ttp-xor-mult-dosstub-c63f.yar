rule TTP_XOR_MULT_DOSStub_c63f {
  strings:
    $key_c63f = { 92 57 [2] e6 4f [2] a1 4d [2] e6 5c [2] a8 50 [2] a4 5a [2] b3 51 [2] a8 1f [2] 95 }

  condition:
    any of them
}