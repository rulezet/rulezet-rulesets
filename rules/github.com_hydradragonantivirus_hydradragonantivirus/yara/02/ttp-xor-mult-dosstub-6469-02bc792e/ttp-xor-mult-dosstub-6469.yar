rule TTP_XOR_MULT_DOSStub_6469 {
  strings:
    $key_6469 = { 30 01 [2] 44 19 [2] 03 1b [2] 44 0a [2] 0a 06 [2] 06 0c [2] 11 07 [2] 0a 49 [2] 37 }

  condition:
    any of them
}