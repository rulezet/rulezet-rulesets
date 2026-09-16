rule TTP_XOR_MULT_DOSStub_5d02 {
  strings:
    $key_5d02 = { 09 6a [2] 7d 72 [2] 3a 70 [2] 7d 61 [2] 33 6d [2] 3f 67 [2] 28 6c [2] 33 22 [2] 0e }

  condition:
    any of them
}