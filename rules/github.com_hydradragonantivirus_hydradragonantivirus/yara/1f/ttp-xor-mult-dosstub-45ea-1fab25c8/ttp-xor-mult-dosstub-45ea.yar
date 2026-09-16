rule TTP_XOR_MULT_DOSStub_45ea {
  strings:
    $key_45ea = { 11 82 [2] 65 9a [2] 22 98 [2] 65 89 [2] 2b 85 [2] 27 8f [2] 30 84 [2] 2b ca [2] 16 }

  condition:
    any of them
}