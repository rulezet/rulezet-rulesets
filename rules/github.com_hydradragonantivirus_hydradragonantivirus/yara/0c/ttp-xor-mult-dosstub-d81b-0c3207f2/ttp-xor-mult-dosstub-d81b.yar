rule TTP_XOR_MULT_DOSStub_d81b {
  strings:
    $key_d81b = { 8c 73 [2] f8 6b [2] bf 69 [2] f8 78 [2] b6 74 [2] ba 7e [2] ad 75 [2] b6 3b [2] 8b }

  condition:
    any of them
}