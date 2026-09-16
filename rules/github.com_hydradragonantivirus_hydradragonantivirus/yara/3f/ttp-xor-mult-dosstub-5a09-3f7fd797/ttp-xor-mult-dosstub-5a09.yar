rule TTP_XOR_MULT_DOSStub_5a09 {
  strings:
    $key_5a09 = { 0e 61 [2] 7a 79 [2] 3d 7b [2] 7a 6a [2] 34 66 [2] 38 6c [2] 2f 67 [2] 34 29 [2] 09 }

  condition:
    any of them
}