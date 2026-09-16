rule TTP_XOR_MULT_DOSStub_3210 {
  strings:
    $key_3210 = { 66 78 [2] 12 60 [2] 55 62 [2] 12 73 [2] 5c 7f [2] 50 75 [2] 47 7e [2] 5c 30 [2] 61 }

  condition:
    any of them
}