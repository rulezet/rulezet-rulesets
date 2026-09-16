rule TTP_XOR_MULT_DOSStub_3414 {
  strings:
    $key_3414 = { 60 7c [2] 14 64 [2] 53 66 [2] 14 77 [2] 5a 7b [2] 56 71 [2] 41 7a [2] 5a 34 [2] 67 }

  condition:
    any of them
}