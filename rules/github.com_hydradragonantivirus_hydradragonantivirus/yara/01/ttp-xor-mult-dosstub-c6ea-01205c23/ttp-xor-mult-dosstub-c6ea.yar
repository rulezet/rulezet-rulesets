rule TTP_XOR_MULT_DOSStub_c6ea {
  strings:
    $key_c6ea = { 92 82 [2] e6 9a [2] a1 98 [2] e6 89 [2] a8 85 [2] a4 8f [2] b3 84 [2] a8 ca [2] 95 }

  condition:
    any of them
}