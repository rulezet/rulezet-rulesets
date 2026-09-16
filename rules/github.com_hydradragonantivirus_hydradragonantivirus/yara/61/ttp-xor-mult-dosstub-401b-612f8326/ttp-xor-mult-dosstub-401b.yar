rule TTP_XOR_MULT_DOSStub_401b {
  strings:
    $key_401b = { 14 73 [2] 60 6b [2] 27 69 [2] 60 78 [2] 2e 74 [2] 22 7e [2] 35 75 [2] 2e 3b [2] 13 }

  condition:
    any of them
}