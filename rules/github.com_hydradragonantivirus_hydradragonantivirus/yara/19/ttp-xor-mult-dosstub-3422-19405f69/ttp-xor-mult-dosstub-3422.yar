rule TTP_XOR_MULT_DOSStub_3422 {
  strings:
    $key_3422 = { 60 4a [2] 14 52 [2] 53 50 [2] 14 41 [2] 5a 4d [2] 56 47 [2] 41 4c [2] 5a 02 [2] 67 }

  condition:
    any of them
}