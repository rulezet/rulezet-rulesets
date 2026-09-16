rule TTP_XOR_MULT_DOSStub_7616 {
  strings:
    $key_7616 = { 22 7e [2] 56 66 [2] 11 64 [2] 56 75 [2] 18 79 [2] 14 73 [2] 03 78 [2] 18 36 [2] 25 }

  condition:
    any of them
}