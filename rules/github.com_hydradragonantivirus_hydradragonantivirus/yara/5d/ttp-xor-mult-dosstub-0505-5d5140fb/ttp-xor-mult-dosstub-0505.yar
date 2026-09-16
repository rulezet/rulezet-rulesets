rule TTP_XOR_MULT_DOSStub_0505 {
  strings:
    $key_0505 = { 51 6d [2] 25 75 [2] 62 77 [2] 25 66 [2] 6b 6a [2] 67 60 [2] 70 6b [2] 6b 25 [2] 56 }

  condition:
    any of them
}