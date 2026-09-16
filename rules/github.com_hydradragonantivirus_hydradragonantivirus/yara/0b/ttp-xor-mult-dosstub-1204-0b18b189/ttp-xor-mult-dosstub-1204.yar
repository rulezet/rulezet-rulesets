rule TTP_XOR_MULT_DOSStub_1204 {
  strings:
    $key_1204 = { 46 6c [2] 32 74 [2] 75 76 [2] 32 67 [2] 7c 6b [2] 70 61 [2] 67 6a [2] 7c 24 [2] 41 }

  condition:
    any of them
}