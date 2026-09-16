rule TTP_XOR_MULT_DOSStub_ffbb {
  strings:
    $key_ffbb = { ab d3 [2] df cb [2] 98 c9 [2] df d8 [2] 91 d4 [2] 9d de [2] 8a d5 [2] 91 9b [2] ac }

  condition:
    any of them
}