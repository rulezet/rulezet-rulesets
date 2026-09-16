rule TTP_XOR_MULT_DOSStub_6609 {
  strings:
    $key_6609 = { 32 61 [2] 46 79 [2] 01 7b [2] 46 6a [2] 08 66 [2] 04 6c [2] 13 67 [2] 08 29 [2] 35 }

  condition:
    any of them
}