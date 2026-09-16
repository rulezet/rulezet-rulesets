rule TTP_XOR_MULT_DOSStub_20ea {
  strings:
    $key_20ea = { 74 82 [2] 00 9a [2] 47 98 [2] 00 89 [2] 4e 85 [2] 42 8f [2] 55 84 [2] 4e ca [2] 73 }

  condition:
    any of them
}