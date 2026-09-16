rule TTP_XOR_MULT_DOSStub_3e75 {
  strings:
    $key_3e75 = { 6a 1d [2] 1e 05 [2] 59 07 [2] 1e 16 [2] 50 1a [2] 5c 10 [2] 4b 1b [2] 50 55 [2] 6d }

  condition:
    any of them
}