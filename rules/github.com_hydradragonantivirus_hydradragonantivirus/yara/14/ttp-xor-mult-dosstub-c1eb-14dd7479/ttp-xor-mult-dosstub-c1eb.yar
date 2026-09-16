rule TTP_XOR_MULT_DOSStub_c1eb {
  strings:
    $key_c1eb = { 95 83 [2] e1 9b [2] a6 99 [2] e1 88 [2] af 84 [2] a3 8e [2] b4 85 [2] af cb [2] 92 }

  condition:
    any of them
}