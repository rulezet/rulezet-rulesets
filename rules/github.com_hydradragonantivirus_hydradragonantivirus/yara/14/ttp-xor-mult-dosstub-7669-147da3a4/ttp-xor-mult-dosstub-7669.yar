rule TTP_XOR_MULT_DOSStub_7669 {
  strings:
    $key_7669 = { 22 01 [2] 56 19 [2] 11 1b [2] 56 0a [2] 18 06 [2] 14 0c [2] 03 07 [2] 18 49 [2] 25 }

  condition:
    any of them
}