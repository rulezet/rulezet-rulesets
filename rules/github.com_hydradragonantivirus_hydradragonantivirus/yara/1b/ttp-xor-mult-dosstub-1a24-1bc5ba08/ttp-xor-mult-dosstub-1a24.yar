rule TTP_XOR_MULT_DOSStub_1a24 {
  strings:
    $key_1a24 = { 4e 4c [2] 3a 54 [2] 7d 56 [2] 3a 47 [2] 74 4b [2] 78 41 [2] 6f 4a [2] 74 04 [2] 49 }

  condition:
    any of them
}