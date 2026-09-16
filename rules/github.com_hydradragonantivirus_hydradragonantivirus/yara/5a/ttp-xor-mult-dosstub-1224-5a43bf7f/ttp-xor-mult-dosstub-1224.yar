rule TTP_XOR_MULT_DOSStub_1224 {
  strings:
    $key_1224 = { 46 4c [2] 32 54 [2] 75 56 [2] 32 47 [2] 7c 4b [2] 70 41 [2] 67 4a [2] 7c 04 [2] 41 }

  condition:
    any of them
}