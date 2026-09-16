rule TTP_XOR_MULT_DOSStub_0525 {
  strings:
    $key_0525 = { 51 4d [2] 25 55 [2] 62 57 [2] 25 46 [2] 6b 4a [2] 67 40 [2] 70 4b [2] 6b 05 [2] 56 }

  condition:
    any of them
}