rule TTP_XOR_MULT_DOSStub_77ea {
  strings:
    $key_77ea = { 23 82 [2] 57 9a [2] 10 98 [2] 57 89 [2] 19 85 [2] 15 8f [2] 02 84 [2] 19 ca [2] 24 }

  condition:
    any of them
}