rule TTP_XOR_MULT_DOSStub_4110 {
  strings:
    $key_4110 = { 15 78 [2] 61 60 [2] 26 62 [2] 61 73 [2] 2f 7f [2] 23 75 [2] 34 7e [2] 2f 30 [2] 12 }

  condition:
    any of them
}