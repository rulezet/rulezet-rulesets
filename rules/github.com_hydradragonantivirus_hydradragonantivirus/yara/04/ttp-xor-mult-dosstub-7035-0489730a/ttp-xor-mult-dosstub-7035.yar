rule TTP_XOR_MULT_DOSStub_7035 {
  strings:
    $key_7035 = { 24 5d [2] 50 45 [2] 17 47 [2] 50 56 [2] 1e 5a [2] 12 50 [2] 05 5b [2] 1e 15 [2] 23 }

  condition:
    any of them
}