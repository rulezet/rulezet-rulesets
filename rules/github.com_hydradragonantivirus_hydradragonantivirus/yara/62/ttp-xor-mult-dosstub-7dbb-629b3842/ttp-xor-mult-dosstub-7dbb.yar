rule TTP_XOR_MULT_DOSStub_7dbb {
  strings:
    $key_7dbb = { 29 d3 [2] 5d cb [2] 1a c9 [2] 5d d8 [2] 13 d4 [2] 1f de [2] 08 d5 [2] 13 9b [2] 2e }

  condition:
    any of them
}