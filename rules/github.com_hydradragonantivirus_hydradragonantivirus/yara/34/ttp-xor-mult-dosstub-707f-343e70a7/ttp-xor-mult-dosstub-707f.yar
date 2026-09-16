rule TTP_XOR_MULT_DOSStub_707f {
  strings:
    $key_707f = { 24 17 [2] 50 0f [2] 17 0d [2] 50 1c [2] 1e 10 [2] 12 1a [2] 05 11 [2] 1e 5f [2] 23 }

  condition:
    any of them
}