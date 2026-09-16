rule TTP_XOR_MULT_DOSStub_1228 {
  strings:
    $key_1228 = { 46 40 [2] 32 58 [2] 75 5a [2] 32 4b [2] 7c 47 [2] 70 4d [2] 67 46 [2] 7c 08 [2] 41 }

  condition:
    any of them
}