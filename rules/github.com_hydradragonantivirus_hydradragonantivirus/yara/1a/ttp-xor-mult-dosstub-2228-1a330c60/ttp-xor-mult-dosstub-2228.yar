rule TTP_XOR_MULT_DOSStub_2228 {
  strings:
    $key_2228 = { 76 40 [2] 02 58 [2] 45 5a [2] 02 4b [2] 4c 47 [2] 40 4d [2] 57 46 [2] 4c 08 [2] 71 }

  condition:
    any of them
}