rule TTP_XOR_MULT_DOSStub_6508 {
  strings:
    $key_6508 = { 31 60 [2] 45 78 [2] 02 7a [2] 45 6b [2] 0b 67 [2] 07 6d [2] 10 66 [2] 0b 28 [2] 36 }

  condition:
    any of them
}