rule TTP_XOR_MULT_DOSStub_5269 {
  strings:
    $key_5269 = { 06 01 [2] 72 19 [2] 35 1b [2] 72 0a [2] 3c 06 [2] 30 0c [2] 27 07 [2] 3c 49 [2] 01 }

  condition:
    any of them
}