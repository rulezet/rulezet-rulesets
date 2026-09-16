rule TTP_XOR_MULT_DOSStub_4d02 {
  strings:
    $key_4d02 = { 19 6a [2] 6d 72 [2] 2a 70 [2] 6d 61 [2] 23 6d [2] 2f 67 [2] 38 6c [2] 23 22 [2] 1e }

  condition:
    any of them
}