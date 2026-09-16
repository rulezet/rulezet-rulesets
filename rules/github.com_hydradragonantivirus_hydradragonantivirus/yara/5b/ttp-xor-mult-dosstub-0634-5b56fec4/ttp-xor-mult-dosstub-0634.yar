rule TTP_XOR_MULT_DOSStub_0634 {
  strings:
    $key_0634 = { 52 5c [2] 26 44 [2] 61 46 [2] 26 57 [2] 68 5b [2] 64 51 [2] 73 5a [2] 68 14 [2] 55 }

  condition:
    any of them
}