rule TTP_XOR_MULT_DOSStub_7a08 {
  strings:
    $key_7a08 = { 2e 60 [2] 5a 78 [2] 1d 7a [2] 5a 6b [2] 14 67 [2] 18 6d [2] 0f 66 [2] 14 28 [2] 29 }

  condition:
    any of them
}