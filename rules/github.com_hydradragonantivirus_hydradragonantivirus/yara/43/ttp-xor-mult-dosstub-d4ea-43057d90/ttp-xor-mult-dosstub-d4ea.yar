rule TTP_XOR_MULT_DOSStub_d4ea {
  strings:
    $key_d4ea = { 80 82 [2] f4 9a [2] b3 98 [2] f4 89 [2] ba 85 [2] b6 8f [2] a1 84 [2] ba ca [2] 87 }

  condition:
    any of them
}