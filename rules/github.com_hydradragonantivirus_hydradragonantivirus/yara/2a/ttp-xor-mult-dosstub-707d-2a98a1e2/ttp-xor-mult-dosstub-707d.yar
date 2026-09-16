rule TTP_XOR_MULT_DOSStub_707d {
  strings:
    $key_707d = { 24 15 [2] 50 0d [2] 17 0f [2] 50 1e [2] 1e 12 [2] 12 18 [2] 05 13 [2] 1e 5d [2] 23 }

  condition:
    any of them
}