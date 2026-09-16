rule TTP_XOR_MULT_DOSStub_1a08 {
  strings:
    $key_1a08 = { 4e 60 [2] 3a 78 [2] 7d 7a [2] 3a 6b [2] 74 67 [2] 78 6d [2] 6f 66 [2] 74 28 [2] 49 }

  condition:
    any of them
}