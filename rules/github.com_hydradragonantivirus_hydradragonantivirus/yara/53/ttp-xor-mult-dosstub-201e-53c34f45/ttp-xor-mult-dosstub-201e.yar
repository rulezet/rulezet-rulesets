rule TTP_XOR_MULT_DOSStub_201e {
  strings:
    $key_201e = { 74 76 [2] 00 6e [2] 47 6c [2] 00 7d [2] 4e 71 [2] 42 7b [2] 55 70 [2] 4e 3e [2] 73 }

  condition:
    any of them
}