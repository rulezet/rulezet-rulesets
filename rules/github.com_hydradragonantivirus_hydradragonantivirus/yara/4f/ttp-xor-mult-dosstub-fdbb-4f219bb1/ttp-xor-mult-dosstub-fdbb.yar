rule TTP_XOR_MULT_DOSStub_fdbb {
  strings:
    $key_fdbb = { a9 d3 [2] dd cb [2] 9a c9 [2] dd d8 [2] 93 d4 [2] 9f de [2] 88 d5 [2] 93 9b [2] ae }

  condition:
    any of them
}