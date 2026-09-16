rule TTP_XOR_MULT_DOSStub_2960 {
  strings:
    $key_2960 = { 7d 08 [2] 09 10 [2] 4e 12 [2] 09 03 [2] 47 0f [2] 4b 05 [2] 5c 0e [2] 47 40 [2] 7a }

  condition:
    any of them
}