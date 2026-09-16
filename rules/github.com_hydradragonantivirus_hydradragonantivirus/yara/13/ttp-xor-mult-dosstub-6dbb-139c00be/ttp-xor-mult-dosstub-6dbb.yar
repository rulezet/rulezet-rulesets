rule TTP_XOR_MULT_DOSStub_6dbb {
  strings:
    $key_6dbb = { 39 d3 [2] 4d cb [2] 0a c9 [2] 4d d8 [2] 03 d4 [2] 0f de [2] 18 d5 [2] 03 9b [2] 3e }

  condition:
    any of them
}