rule TTP_XOR_MULT_DOSStub_2110 {
  strings:
    $key_2110 = { 75 78 [2] 01 60 [2] 46 62 [2] 01 73 [2] 4f 7f [2] 43 75 [2] 54 7e [2] 4f 30 [2] 72 }

  condition:
    any of them
}