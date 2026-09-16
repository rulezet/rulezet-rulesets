rule TTP_XOR_MULT_DOSStub_2223 {
  strings:
    $key_2223 = { 76 4b [2] 02 53 [2] 45 51 [2] 02 40 [2] 4c 4c [2] 40 46 [2] 57 4d [2] 4c 03 [2] 71 }

  condition:
    any of them
}