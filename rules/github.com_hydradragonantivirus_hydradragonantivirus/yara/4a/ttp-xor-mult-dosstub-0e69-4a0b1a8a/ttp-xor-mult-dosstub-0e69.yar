rule TTP_XOR_MULT_DOSStub_0e69 {
  strings:
    $key_0e69 = { 5a 01 [2] 2e 19 [2] 69 1b [2] 2e 0a [2] 60 06 [2] 6c 0c [2] 7b 07 [2] 60 49 [2] 5d }

  condition:
    any of them
}