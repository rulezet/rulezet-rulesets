rule TTP_XOR_MULT_DOSStub_1a22 {
  strings:
    $key_1a22 = { 4e 4a [2] 3a 52 [2] 7d 50 [2] 3a 41 [2] 74 4d [2] 78 47 [2] 6f 4c [2] 74 02 [2] 49 }

  condition:
    any of them
}