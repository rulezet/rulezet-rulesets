rule TTP_XOR_MULT_DOSStub_0862 {
  strings:
    $key_0862 = { 5c 0a [2] 28 12 [2] 6f 10 [2] 28 01 [2] 66 0d [2] 6a 07 [2] 7d 0c [2] 66 42 [2] 5b }

  condition:
    any of them
}