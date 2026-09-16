rule TTP_XOR_MULT_DOSStub_407c {
  strings:
    $key_407c = { 14 14 [2] 60 0c [2] 27 0e [2] 60 1f [2] 2e 13 [2] 22 19 [2] 35 12 [2] 2e 5c [2] 13 }

  condition:
    any of them
}