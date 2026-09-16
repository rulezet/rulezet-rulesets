rule TTP_XOR_MULT_DOSStub_5602 {
  strings:
    $key_5602 = { 02 6a [2] 76 72 [2] 31 70 [2] 76 61 [2] 38 6d [2] 34 67 [2] 23 6c [2] 38 22 [2] 05 }

  condition:
    any of them
}