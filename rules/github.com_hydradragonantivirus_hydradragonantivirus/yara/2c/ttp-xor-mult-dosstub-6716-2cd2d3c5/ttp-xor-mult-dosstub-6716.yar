rule TTP_XOR_MULT_DOSStub_6716 {
  strings:
    $key_6716 = { 33 7e [2] 47 66 [2] 00 64 [2] 47 75 [2] 09 79 [2] 05 73 [2] 12 78 [2] 09 36 [2] 34 }

  condition:
    any of them
}