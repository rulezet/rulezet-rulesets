rule TTP_XOR_MULT_DOSStub_4660 {
  strings:
    $key_4660 = { 12 08 [2] 66 10 [2] 21 12 [2] 66 03 [2] 28 0f [2] 24 05 [2] 33 0e [2] 28 40 [2] 15 }

  condition:
    any of them
}