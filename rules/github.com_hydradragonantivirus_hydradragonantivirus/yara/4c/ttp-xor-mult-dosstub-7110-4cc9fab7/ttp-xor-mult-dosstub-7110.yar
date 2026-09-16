rule TTP_XOR_MULT_DOSStub_7110 {
  strings:
    $key_7110 = { 25 78 [2] 51 60 [2] 16 62 [2] 51 73 [2] 1f 7f [2] 13 75 [2] 04 7e [2] 1f 30 [2] 22 }

  condition:
    any of them
}