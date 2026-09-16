rule TTP_XOR_MULT_DOSStub_6260 {
  strings:
    $key_6260 = { 36 08 [2] 42 10 [2] 05 12 [2] 42 03 [2] 0c 0f [2] 00 05 [2] 17 0e [2] 0c 40 [2] 31 }

  condition:
    any of them
}