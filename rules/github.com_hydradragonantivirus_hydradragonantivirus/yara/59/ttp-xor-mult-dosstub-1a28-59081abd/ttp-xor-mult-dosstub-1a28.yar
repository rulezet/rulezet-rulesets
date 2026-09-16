rule TTP_XOR_MULT_DOSStub_1a28 {
  strings:
    $key_1a28 = { 4e 40 [2] 3a 58 [2] 7d 5a [2] 3a 4b [2] 74 47 [2] 78 4d [2] 6f 46 [2] 74 08 [2] 49 }

  condition:
    any of them
}