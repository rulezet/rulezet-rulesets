rule TTP_XOR_MULT_DOSStub_2e18 {
  strings:
    $key_2e18 = { 7a 70 [2] 0e 68 [2] 49 6a [2] 0e 7b [2] 40 77 [2] 4c 7d [2] 5b 76 [2] 40 38 [2] 7d }

  condition:
    any of them
}