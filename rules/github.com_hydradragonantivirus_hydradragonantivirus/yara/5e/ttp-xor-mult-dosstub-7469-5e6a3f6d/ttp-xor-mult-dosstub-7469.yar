rule TTP_XOR_MULT_DOSStub_7469 {
  strings:
    $key_7469 = { 20 01 [2] 54 19 [2] 13 1b [2] 54 0a [2] 1a 06 [2] 16 0c [2] 01 07 [2] 1a 49 [2] 27 }

  condition:
    any of them
}