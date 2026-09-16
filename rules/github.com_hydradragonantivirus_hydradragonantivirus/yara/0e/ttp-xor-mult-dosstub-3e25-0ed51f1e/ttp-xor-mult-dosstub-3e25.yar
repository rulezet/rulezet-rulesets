rule TTP_XOR_MULT_DOSStub_3e25 {
  strings:
    $key_3e25 = { 6a 4d [2] 1e 55 [2] 59 57 [2] 1e 46 [2] 50 4a [2] 5c 40 [2] 4b 4b [2] 50 05 [2] 6d }

  condition:
    any of them
}