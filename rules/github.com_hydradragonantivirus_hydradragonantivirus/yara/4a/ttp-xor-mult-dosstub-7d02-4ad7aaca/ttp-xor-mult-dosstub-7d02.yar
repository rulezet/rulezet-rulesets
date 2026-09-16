rule TTP_XOR_MULT_DOSStub_7d02 {
  strings:
    $key_7d02 = { 29 6a [2] 5d 72 [2] 1a 70 [2] 5d 61 [2] 13 6d [2] 1f 67 [2] 08 6c [2] 13 22 [2] 2e }

  condition:
    any of them
}