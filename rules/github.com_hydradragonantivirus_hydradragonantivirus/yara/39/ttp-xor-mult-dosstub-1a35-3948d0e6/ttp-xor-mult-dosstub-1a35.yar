rule TTP_XOR_MULT_DOSStub_1a35 {
  strings:
    $key_1a35 = { 4e 5d [2] 3a 45 [2] 7d 47 [2] 3a 56 [2] 74 5a [2] 78 50 [2] 6f 5b [2] 74 15 [2] 49 }

  condition:
    any of them
}