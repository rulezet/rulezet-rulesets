rule TTP_XOR_MULT_DOSStub_6269 {
  strings:
    $key_6269 = { 36 01 [2] 42 19 [2] 05 1b [2] 42 0a [2] 0c 06 [2] 00 0c [2] 17 07 [2] 0c 49 [2] 31 }

  condition:
    any of them
}