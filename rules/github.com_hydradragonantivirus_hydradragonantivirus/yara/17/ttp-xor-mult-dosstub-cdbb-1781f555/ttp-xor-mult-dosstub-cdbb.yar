rule TTP_XOR_MULT_DOSStub_cdbb {
  strings:
    $key_cdbb = { 99 d3 [2] ed cb [2] aa c9 [2] ed d8 [2] a3 d4 [2] af de [2] b8 d5 [2] a3 9b [2] 9e }

  condition:
    any of them
}