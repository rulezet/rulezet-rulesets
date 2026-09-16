rule TTP_XOR_MULT_DOSStub_703f {
  strings:
    $key_703f = { 24 57 [2] 50 4f [2] 17 4d [2] 50 5c [2] 1e 50 [2] 12 5a [2] 05 51 [2] 1e 1f [2] 23 }

  condition:
    any of them
}