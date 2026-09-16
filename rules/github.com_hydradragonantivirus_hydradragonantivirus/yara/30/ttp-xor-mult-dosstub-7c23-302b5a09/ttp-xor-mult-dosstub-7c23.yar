rule TTP_XOR_MULT_DOSStub_7c23 {
  strings:
    $key_7c23 = { 28 4b [2] 5c 53 [2] 1b 51 [2] 5c 40 [2] 12 4c [2] 1e 46 [2] 09 4d [2] 12 03 [2] 2f }

  condition:
    any of them
}