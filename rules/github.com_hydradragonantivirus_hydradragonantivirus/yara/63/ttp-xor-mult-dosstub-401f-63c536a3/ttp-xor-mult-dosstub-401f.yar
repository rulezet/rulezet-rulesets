rule TTP_XOR_MULT_DOSStub_401f {
  strings:
    $key_401f = { 14 77 [2] 60 6f [2] 27 6d [2] 60 7c [2] 2e 70 [2] 22 7a [2] 35 71 [2] 2e 3f [2] 13 }

  condition:
    any of them
}