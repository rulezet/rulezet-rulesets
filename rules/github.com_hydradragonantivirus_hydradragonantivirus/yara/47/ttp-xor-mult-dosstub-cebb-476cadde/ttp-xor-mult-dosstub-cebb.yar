rule TTP_XOR_MULT_DOSStub_cebb {
  strings:
    $key_cebb = { 9a d3 [2] ee cb [2] a9 c9 [2] ee d8 [2] a0 d4 [2] ac de [2] bb d5 [2] a0 9b [2] 9d }

  condition:
    any of them
}