rule TTP_XOR_MULT_DOSStub_5a32 {
  strings:
    $key_5a32 = { 0e 5a [2] 7a 42 [2] 3d 40 [2] 7a 51 [2] 34 5d [2] 38 57 [2] 2f 5c [2] 34 12 [2] 09 }

  condition:
    any of them
}