rule TTP_XOR_MULT_DOSStub_3415 {
  strings:
    $key_3415 = { 60 7d [2] 14 65 [2] 53 67 [2] 14 76 [2] 5a 7a [2] 56 70 [2] 41 7b [2] 5a 35 [2] 67 }

  condition:
    any of them
}