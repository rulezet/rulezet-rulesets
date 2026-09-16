rule TTP_XOR_MULT_DOSStub_763f {
  strings:
    $key_763f = { 22 57 [2] 56 4f [2] 11 4d [2] 56 5c [2] 18 50 [2] 14 5a [2] 03 51 [2] 18 1f [2] 25 }

  condition:
    any of them
}