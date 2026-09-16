rule TTP_XOR_MULT_DOSStub_6250 {
  strings:
    $key_6250 = { 36 38 [2] 42 20 [2] 05 22 [2] 42 33 [2] 0c 3f [2] 00 35 [2] 17 3e [2] 0c 70 [2] 31 }

  condition:
    any of them
}