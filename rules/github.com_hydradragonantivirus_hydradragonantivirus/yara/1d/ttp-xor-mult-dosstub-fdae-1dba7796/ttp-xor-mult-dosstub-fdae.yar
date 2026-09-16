rule TTP_XOR_MULT_DOSStub_fdae {
  strings:
    $key_fdae = { a9 c6 [2] dd de [2] 9a dc [2] dd cd [2] 93 c1 [2] 9f cb [2] 88 c0 [2] 93 8e [2] ae }

  condition:
    any of them
}