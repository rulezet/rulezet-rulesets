rule TTP_XOR_MULT_DOSStub_1a13 {
  strings:
    $key_1a13 = { 4e 7b [2] 3a 63 [2] 7d 61 [2] 3a 70 [2] 74 7c [2] 78 76 [2] 6f 7d [2] 74 33 [2] 49 }

  condition:
    any of them
}