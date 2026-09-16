rule TTP_XOR_MULT_DOSStub_1222 {
  strings:
    $key_1222 = { 46 4a [2] 32 52 [2] 75 50 [2] 32 41 [2] 7c 4d [2] 70 47 [2] 67 4c [2] 7c 02 [2] 41 }

  condition:
    any of them
}