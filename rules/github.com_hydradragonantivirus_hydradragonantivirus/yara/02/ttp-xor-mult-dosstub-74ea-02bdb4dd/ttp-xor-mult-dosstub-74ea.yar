rule TTP_XOR_MULT_DOSStub_74ea {
  strings:
    $key_74ea = { 20 82 [2] 54 9a [2] 13 98 [2] 54 89 [2] 1a 85 [2] 16 8f [2] 01 84 [2] 1a ca [2] 27 }

  condition:
    any of them
}