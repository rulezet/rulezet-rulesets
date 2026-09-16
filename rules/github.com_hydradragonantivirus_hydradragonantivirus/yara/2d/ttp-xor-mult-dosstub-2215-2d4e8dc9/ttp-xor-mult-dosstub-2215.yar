rule TTP_XOR_MULT_DOSStub_2215 {
  strings:
    $key_2215 = { 76 7d [2] 02 65 [2] 45 67 [2] 02 76 [2] 4c 7a [2] 40 70 [2] 57 7b [2] 4c 35 [2] 71 }

  condition:
    any of them
}