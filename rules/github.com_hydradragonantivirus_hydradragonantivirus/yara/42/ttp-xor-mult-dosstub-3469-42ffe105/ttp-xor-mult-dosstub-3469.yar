rule TTP_XOR_MULT_DOSStub_3469 {
  strings:
    $key_3469 = { 60 01 [2] 14 19 [2] 53 1b [2] 14 0a [2] 5a 06 [2] 56 0c [2] 41 07 [2] 5a 49 [2] 67 }

  condition:
    any of them
}