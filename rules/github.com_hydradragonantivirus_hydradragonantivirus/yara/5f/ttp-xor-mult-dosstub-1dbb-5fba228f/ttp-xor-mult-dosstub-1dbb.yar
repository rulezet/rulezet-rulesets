rule TTP_XOR_MULT_DOSStub_1dbb {
  strings:
    $key_1dbb = { 49 d3 [2] 3d cb [2] 7a c9 [2] 3d d8 [2] 73 d4 [2] 7f de [2] 68 d5 [2] 73 9b [2] 4e }

  condition:
    any of them
}