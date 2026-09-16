rule TTP_XOR_MULT_DOSStub_0325 {
  strings:
    $key_0325 = { 57 4d [2] 23 55 [2] 64 57 [2] 23 46 [2] 6d 4a [2] 61 40 [2] 76 4b [2] 6d 05 [2] 50 }

  condition:
    any of them
}