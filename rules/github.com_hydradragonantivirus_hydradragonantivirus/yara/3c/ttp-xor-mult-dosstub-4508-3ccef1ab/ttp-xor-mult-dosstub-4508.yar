rule TTP_XOR_MULT_DOSStub_4508 {
  strings:
    $key_4508 = { 11 60 [2] 65 78 [2] 22 7a [2] 65 6b [2] 2b 67 [2] 27 6d [2] 30 66 [2] 2b 28 [2] 16 }

  condition:
    any of them
}