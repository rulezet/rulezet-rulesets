rule TTP_XOR_MULT_DOSStub_5239 {
  strings:
    $key_5239 = { 06 51 [2] 72 49 [2] 35 4b [2] 72 5a [2] 3c 56 [2] 30 5c [2] 27 57 [2] 3c 19 [2] 01 }

  condition:
    any of them
}