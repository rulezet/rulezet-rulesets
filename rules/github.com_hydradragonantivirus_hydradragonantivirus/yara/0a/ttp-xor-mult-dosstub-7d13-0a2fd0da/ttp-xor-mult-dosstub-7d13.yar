rule TTP_XOR_MULT_DOSStub_7d13 {
  strings:
    $key_7d13 = { 29 7b [2] 5d 63 [2] 1a 61 [2] 5d 70 [2] 13 7c [2] 1f 76 [2] 08 7d [2] 13 33 [2] 2e }

  condition:
    any of them
}