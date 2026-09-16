rule TTP_XOR_MULT_DOSStub_3323 {
  strings:
    $key_3323 = { 67 4b [2] 13 53 [2] 54 51 [2] 13 40 [2] 5d 4c [2] 51 46 [2] 46 4d [2] 5d 03 [2] 60 }

  condition:
    any of them
}