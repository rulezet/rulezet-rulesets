rule TTP_XOR_MULT_DOSStub_6c50 {
  strings:
    $key_6c50 = { 38 38 [2] 4c 20 [2] 0b 22 [2] 4c 33 [2] 02 3f [2] 0e 35 [2] 19 3e [2] 02 70 [2] 3f }

  condition:
    any of them
}