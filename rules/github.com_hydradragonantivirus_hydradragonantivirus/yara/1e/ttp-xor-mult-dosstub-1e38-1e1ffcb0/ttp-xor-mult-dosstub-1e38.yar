rule TTP_XOR_MULT_DOSStub_1e38 {
  strings:
    $key_1e38 = { 4a 50 [2] 3e 48 [2] 79 4a [2] 3e 5b [2] 70 57 [2] 7c 5d [2] 6b 56 [2] 70 18 [2] 4d }

  condition:
    any of them
}