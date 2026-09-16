rule TTP_XOR_MULT_DOSStub_2e38 {
  strings:
    $key_2e38 = { 7a 50 [2] 0e 48 [2] 49 4a [2] 0e 5b [2] 40 57 [2] 4c 5d [2] 5b 56 [2] 40 18 [2] 7d }

  condition:
    any of them
}