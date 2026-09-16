rule TTP_XOR_MULT_DOSStub_707c {
  strings:
    $key_707c = { 24 14 [2] 50 0c [2] 17 0e [2] 50 1f [2] 1e 13 [2] 12 19 [2] 05 12 [2] 1e 5c [2] 23 }

  condition:
    any of them
}