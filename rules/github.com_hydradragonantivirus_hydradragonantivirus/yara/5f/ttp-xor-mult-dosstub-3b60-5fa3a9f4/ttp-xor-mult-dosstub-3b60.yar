rule TTP_XOR_MULT_DOSStub_3b60 {
  strings:
    $key_3b60 = { 6f 08 [2] 1b 10 [2] 5c 12 [2] 1b 03 [2] 55 0f [2] 59 05 [2] 4e 0e [2] 55 40 [2] 68 }

  condition:
    any of them
}