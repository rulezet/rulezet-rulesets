rule TTP_XOR_MULT_DOSStub_621f {
  strings:
    $key_621f = { 36 77 [2] 42 6f [2] 05 6d [2] 42 7c [2] 0c 70 [2] 00 7a [2] 17 71 [2] 0c 3f [2] 31 }

  condition:
    any of them
}