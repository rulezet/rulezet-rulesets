rule TTP_XOR_MULT_DOSStub_201f {
  strings:
    $key_201f = { 74 77 [2] 00 6f [2] 47 6d [2] 00 7c [2] 4e 70 [2] 42 7a [2] 55 71 [2] 4e 3f [2] 73 }

  condition:
    any of them
}