rule TTP_XOR_MULT_DOSStub_3110 {
  strings:
    $key_3110 = { 65 78 [2] 11 60 [2] 56 62 [2] 11 73 [2] 5f 7f [2] 53 75 [2] 44 7e [2] 5f 30 [2] 62 }

  condition:
    any of them
}