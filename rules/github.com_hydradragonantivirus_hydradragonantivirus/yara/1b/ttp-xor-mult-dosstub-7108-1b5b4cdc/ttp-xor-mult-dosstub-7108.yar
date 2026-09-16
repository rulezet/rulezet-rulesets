rule TTP_XOR_MULT_DOSStub_7108 {
  strings:
    $key_7108 = { 25 60 [2] 51 78 [2] 16 7a [2] 51 6b [2] 1f 67 [2] 13 6d [2] 04 66 [2] 1f 28 [2] 22 }

  condition:
    any of them
}