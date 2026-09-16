rule TTP_XOR_MULT_DOSStub_c1ea {
  strings:
    $key_c1ea = { 95 82 [2] e1 9a [2] a6 98 [2] e1 89 [2] af 85 [2] a3 8f [2] b4 84 [2] af ca [2] 92 }

  condition:
    any of them
}