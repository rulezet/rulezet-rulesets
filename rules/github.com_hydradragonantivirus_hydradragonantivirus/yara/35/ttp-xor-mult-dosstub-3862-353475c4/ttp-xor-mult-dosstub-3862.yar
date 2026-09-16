rule TTP_XOR_MULT_DOSStub_3862 {
  strings:
    $key_3862 = { 6c 0a [2] 18 12 [2] 5f 10 [2] 18 01 [2] 56 0d [2] 5a 07 [2] 4d 0c [2] 56 42 [2] 6b }

  condition:
    any of them
}