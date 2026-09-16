rule TTP_XOR_MULT_DOSStub_1208 {
  strings:
    $key_1208 = { 46 60 [2] 32 78 [2] 75 7a [2] 32 6b [2] 7c 67 [2] 70 6d [2] 67 66 [2] 7c 28 [2] 41 }

  condition:
    any of them
}