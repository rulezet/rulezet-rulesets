rule TTP_XOR_MULT_DOSStub_3325 {
  strings:
    $key_3325 = { 67 4d [2] 13 55 [2] 54 57 [2] 13 46 [2] 5d 4a [2] 51 40 [2] 46 4b [2] 5d 05 [2] 60 }

  condition:
    any of them
}