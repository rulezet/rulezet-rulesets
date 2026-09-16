rule TTP_XOR_MULT_DOSStub_4d13 {
  strings:
    $key_4d13 = { 19 7b [2] 6d 63 [2] 2a 61 [2] 6d 70 [2] 23 7c [2] 2f 76 [2] 38 7d [2] 23 33 [2] 1e }

  condition:
    any of them
}