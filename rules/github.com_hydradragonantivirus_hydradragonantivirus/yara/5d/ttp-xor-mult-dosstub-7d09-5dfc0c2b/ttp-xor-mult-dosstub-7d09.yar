rule TTP_XOR_MULT_DOSStub_7d09 {
  strings:
    $key_7d09 = { 29 61 [2] 5d 79 [2] 1a 7b [2] 5d 6a [2] 13 66 [2] 1f 6c [2] 08 67 [2] 13 29 [2] 2e }

  condition:
    any of them
}