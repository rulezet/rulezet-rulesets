rule TTP_XOR_MULT_DOSStub_6663 {
  strings:
    $key_6663 = { 32 0b [2] 46 13 [2] 01 11 [2] 46 00 [2] 08 0c [2] 04 06 [2] 13 0d [2] 08 43 [2] 35 }

  condition:
    any of them
}