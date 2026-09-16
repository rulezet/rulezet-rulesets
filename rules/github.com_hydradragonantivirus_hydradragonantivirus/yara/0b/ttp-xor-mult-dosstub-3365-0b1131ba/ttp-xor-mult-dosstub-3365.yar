rule TTP_XOR_MULT_DOSStub_3365 {
  strings:
    $key_3365 = { 67 0d [2] 13 15 [2] 54 17 [2] 13 06 [2] 5d 0a [2] 51 00 [2] 46 0b [2] 5d 45 [2] 60 }

  condition:
    any of them
}