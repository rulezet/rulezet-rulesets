rule TTP_XOR_MULT_DOSStub_3464 {
  strings:
    $key_3464 = { 60 0c [2] 14 14 [2] 53 16 [2] 14 07 [2] 5a 0b [2] 56 01 [2] 41 0a [2] 5a 44 [2] 67 }

  condition:
    any of them
}