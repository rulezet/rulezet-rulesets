rule TTP_XOR_MULT_DOSStub_c62a {
  strings:
    $key_c62a = { 92 42 [2] e6 5a [2] a1 58 [2] e6 49 [2] a8 45 [2] a4 4f [2] b3 44 [2] a8 0a [2] 95 }

  condition:
    any of them
}