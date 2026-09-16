rule TTP_XOR_MULT_DOSStub_8abb {
  strings:
    $key_8abb = { de d3 [2] aa cb [2] ed c9 [2] aa d8 [2] e4 d4 [2] e8 de [2] ff d5 [2] e4 9b [2] d9 }

  condition:
    any of them
}