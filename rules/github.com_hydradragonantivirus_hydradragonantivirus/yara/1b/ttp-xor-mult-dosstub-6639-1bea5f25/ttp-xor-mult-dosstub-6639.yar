rule TTP_XOR_MULT_DOSStub_6639 {
  strings:
    $key_6639 = { 32 51 [2] 46 49 [2] 01 4b [2] 46 5a [2] 08 56 [2] 04 5c [2] 13 57 [2] 08 19 [2] 35 }

  condition:
    any of them
}