rule TTP_XOR_MULT_DOSStub_5e05 {
  strings:
    $key_5e05 = { 0a 6d [2] 7e 75 [2] 39 77 [2] 7e 66 [2] 30 6a [2] 3c 60 [2] 2b 6b [2] 30 25 [2] 0d }

  condition:
    any of them
}