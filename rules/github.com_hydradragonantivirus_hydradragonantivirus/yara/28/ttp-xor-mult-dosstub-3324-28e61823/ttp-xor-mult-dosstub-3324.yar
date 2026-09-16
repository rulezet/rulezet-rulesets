rule TTP_XOR_MULT_DOSStub_3324 {
  strings:
    $key_3324 = { 67 4c [2] 13 54 [2] 54 56 [2] 13 47 [2] 5d 4b [2] 51 41 [2] 46 4a [2] 5d 04 [2] 60 }

  condition:
    any of them
}