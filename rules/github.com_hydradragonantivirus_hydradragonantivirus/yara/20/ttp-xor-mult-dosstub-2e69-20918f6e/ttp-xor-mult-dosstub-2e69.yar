rule TTP_XOR_MULT_DOSStub_2e69 {
  strings:
    $key_2e69 = { 7a 01 [2] 0e 19 [2] 49 1b [2] 0e 0a [2] 40 06 [2] 4c 0c [2] 5b 07 [2] 40 49 [2] 7d }

  condition:
    any of them
}