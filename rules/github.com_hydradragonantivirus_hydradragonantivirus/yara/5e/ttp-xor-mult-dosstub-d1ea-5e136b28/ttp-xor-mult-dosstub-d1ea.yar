rule TTP_XOR_MULT_DOSStub_d1ea {
  strings:
    $key_d1ea = { 85 82 [2] f1 9a [2] b6 98 [2] f1 89 [2] bf 85 [2] b3 8f [2] a4 84 [2] bf ca [2] 82 }

  condition:
    any of them
}