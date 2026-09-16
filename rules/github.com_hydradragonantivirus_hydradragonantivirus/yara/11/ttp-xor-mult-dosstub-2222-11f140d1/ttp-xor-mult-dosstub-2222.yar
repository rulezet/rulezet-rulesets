rule TTP_XOR_MULT_DOSStub_2222 {
  strings:
    $key_2222 = { 76 4a [2] 02 52 [2] 45 50 [2] 02 41 [2] 4c 4d [2] 40 47 [2] 57 4c [2] 4c 02 [2] 71 }

  condition:
    any of them
}