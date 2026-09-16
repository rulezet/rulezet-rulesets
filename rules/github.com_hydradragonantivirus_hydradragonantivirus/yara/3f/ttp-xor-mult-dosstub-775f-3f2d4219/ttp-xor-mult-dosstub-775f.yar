rule TTP_XOR_MULT_DOSStub_775f {
  strings:
    $key_775f = { 23 37 [2] 57 2f [2] 10 2d [2] 57 3c [2] 19 30 [2] 15 3a [2] 02 31 [2] 19 7f [2] 24 }

  condition:
    any of them
}