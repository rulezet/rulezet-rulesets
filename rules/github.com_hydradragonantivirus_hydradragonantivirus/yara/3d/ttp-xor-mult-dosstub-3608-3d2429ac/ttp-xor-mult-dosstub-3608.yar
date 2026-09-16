rule TTP_XOR_MULT_DOSStub_3608 {
  strings:
    $key_3608 = { 62 60 [2] 16 78 [2] 51 7a [2] 16 6b [2] 58 67 [2] 54 6d [2] 43 66 [2] 58 28 [2] 65 }

  condition:
    any of them
}