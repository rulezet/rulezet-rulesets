rule TTP_XOR_MULT_DOSStub_c66a {
  strings:
    $key_c66a = { 92 02 [2] e6 1a [2] a1 18 [2] e6 09 [2] a8 05 [2] a4 0f [2] b3 04 [2] a8 4a [2] 95 }

  condition:
    any of them
}