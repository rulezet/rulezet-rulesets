rule TTP_XOR_MULT_DOSStub_3413 {
  strings:
    $key_3413 = { 60 7b [2] 14 63 [2] 53 61 [2] 14 70 [2] 5a 7c [2] 56 76 [2] 41 7d [2] 5a 33 [2] 67 }

  condition:
    any of them
}