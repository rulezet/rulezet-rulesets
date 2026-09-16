rule TTP_XOR_MULT_DOSStub_4c28 {
  strings:
    $key_4c28 = { 18 40 [2] 6c 58 [2] 2b 5a [2] 6c 4b [2] 22 47 [2] 2e 4d [2] 39 46 [2] 22 08 [2] 1f }

  condition:
    any of them
}