rule TTP_XOR_MULT_DOSStub_3424 {
  strings:
    $key_3424 = { 60 4c [2] 14 54 [2] 53 56 [2] 14 47 [2] 5a 4b [2] 56 41 [2] 41 4a [2] 5a 04 [2] 67 }

  condition:
    any of them
}