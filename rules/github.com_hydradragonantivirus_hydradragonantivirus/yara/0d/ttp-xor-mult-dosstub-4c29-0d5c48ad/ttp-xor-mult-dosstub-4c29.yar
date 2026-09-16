rule TTP_XOR_MULT_DOSStub_4c29 {
  strings:
    $key_4c29 = { 18 41 [2] 6c 59 [2] 2b 5b [2] 6c 4a [2] 22 46 [2] 2e 4c [2] 39 47 [2] 22 09 [2] 1f }

  condition:
    any of them
}