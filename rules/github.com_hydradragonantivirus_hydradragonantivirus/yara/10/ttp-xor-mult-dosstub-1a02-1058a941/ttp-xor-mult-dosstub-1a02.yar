rule TTP_XOR_MULT_DOSStub_1a02 {
  strings:
    $key_1a02 = { 4e 6a [2] 3a 72 [2] 7d 70 [2] 3a 61 [2] 74 6d [2] 78 67 [2] 6f 6c [2] 74 22 [2] 49 }

  condition:
    any of them
}