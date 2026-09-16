rule TTP_XOR_MULT_DOSStub_7160 {
  strings:
    $key_7160 = { 25 08 [2] 51 10 [2] 16 12 [2] 51 03 [2] 1f 0f [2] 13 05 [2] 04 0e [2] 1f 40 [2] 22 }

  condition:
    any of them
}