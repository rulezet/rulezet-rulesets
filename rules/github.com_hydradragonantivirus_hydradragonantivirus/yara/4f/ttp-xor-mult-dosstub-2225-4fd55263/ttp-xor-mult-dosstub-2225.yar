rule TTP_XOR_MULT_DOSStub_2225 {
  strings:
    $key_2225 = { 76 4d [2] 02 55 [2] 45 57 [2] 02 46 [2] 4c 4a [2] 40 40 [2] 57 4b [2] 4c 05 [2] 71 }

  condition:
    any of them
}