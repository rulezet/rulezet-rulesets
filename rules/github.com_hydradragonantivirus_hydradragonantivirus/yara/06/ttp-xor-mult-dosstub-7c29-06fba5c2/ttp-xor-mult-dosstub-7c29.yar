rule TTP_XOR_MULT_DOSStub_7c29 {
  strings:
    $key_7c29 = { 28 41 [2] 5c 59 [2] 1b 5b [2] 5c 4a [2] 12 46 [2] 1e 4c [2] 09 47 [2] 12 09 [2] 2f }

  condition:
    any of them
}