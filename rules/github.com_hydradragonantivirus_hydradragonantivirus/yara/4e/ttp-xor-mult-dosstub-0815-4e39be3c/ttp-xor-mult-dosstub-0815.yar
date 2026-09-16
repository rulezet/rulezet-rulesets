rule TTP_XOR_MULT_DOSStub_0815 {
  strings:
    $key_0815 = { 5c 7d [2] 28 65 [2] 6f 67 [2] 28 76 [2] 66 7a [2] 6a 70 [2] 7d 7b [2] 66 35 [2] 5b }

  condition:
    any of them
}