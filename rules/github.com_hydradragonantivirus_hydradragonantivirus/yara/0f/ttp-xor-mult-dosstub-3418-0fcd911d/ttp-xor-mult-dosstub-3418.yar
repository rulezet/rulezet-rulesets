rule TTP_XOR_MULT_DOSStub_3418 {
  strings:
    $key_3418 = { 60 70 [2] 14 68 [2] 53 6a [2] 14 7b [2] 5a 77 [2] 56 7d [2] 41 76 [2] 5a 38 [2] 67 }

  condition:
    any of them
}