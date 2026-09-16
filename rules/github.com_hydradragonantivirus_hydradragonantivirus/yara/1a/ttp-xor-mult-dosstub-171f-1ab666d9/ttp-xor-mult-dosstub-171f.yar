rule TTP_XOR_MULT_DOSStub_171f {
  strings:
    $key_171f = { 43 77 [2] 37 6f [2] 70 6d [2] 37 7c [2] 79 70 [2] 75 7a [2] 62 71 [2] 79 3f [2] 44 }

  condition:
    any of them
}