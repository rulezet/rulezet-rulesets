rule TTP_XOR_MULT_DOSStub_6410 {
  strings:
    $key_6410 = { 30 78 [2] 44 60 [2] 03 62 [2] 44 73 [2] 0a 7f [2] 06 75 [2] 11 7e [2] 0a 30 [2] 37 }

  condition:
    any of them
}