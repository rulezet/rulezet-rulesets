rule TTP_XOR_MULT_DOSStub_a4ea {
  strings:
    $key_a4ea = { f0 82 [2] 84 9a [2] c3 98 [2] 84 89 [2] ca 85 [2] c6 8f [2] d1 84 [2] ca ca [2] f7 }

  condition:
    any of them
}