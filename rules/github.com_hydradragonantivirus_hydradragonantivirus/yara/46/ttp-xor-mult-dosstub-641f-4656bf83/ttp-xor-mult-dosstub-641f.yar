rule TTP_XOR_MULT_DOSStub_641f {
  strings:
    $key_641f = { 30 77 [2] 44 6f [2] 03 6d [2] 44 7c [2] 0a 70 [2] 06 7a [2] 11 71 [2] 0a 3f [2] 37 }

  condition:
    any of them
}