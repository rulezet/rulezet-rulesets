rule TTP_XOR_MULT_DOSStub_0960 {
  strings:
    $key_0960 = { 5d 08 [2] 29 10 [2] 6e 12 [2] 29 03 [2] 67 0f [2] 6b 05 [2] 7c 0e [2] 67 40 [2] 5a }

  condition:
    any of them
}