rule TTP_XOR_MULT_DOSStub_6614 {
  strings:
    $key_6614 = { 32 7c [2] 46 64 [2] 01 66 [2] 46 77 [2] 08 7b [2] 04 71 [2] 13 7a [2] 08 34 [2] 35 }

  condition:
    any of them
}