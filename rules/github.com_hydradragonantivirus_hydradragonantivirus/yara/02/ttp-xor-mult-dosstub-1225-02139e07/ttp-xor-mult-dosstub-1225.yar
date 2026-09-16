rule TTP_XOR_MULT_DOSStub_1225 {
  strings:
    $key_1225 = { 46 4d [2] 32 55 [2] 75 57 [2] 32 46 [2] 7c 4a [2] 70 40 [2] 67 4b [2] 7c 05 [2] 41 }

  condition:
    any of them
}