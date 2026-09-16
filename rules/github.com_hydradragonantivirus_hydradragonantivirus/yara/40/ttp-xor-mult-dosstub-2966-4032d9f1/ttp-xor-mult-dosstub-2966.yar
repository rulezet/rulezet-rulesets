rule TTP_XOR_MULT_DOSStub_2966 {
  strings:
    $key_2966 = { 7d 0e [2] 09 16 [2] 4e 14 [2] 09 05 [2] 47 09 [2] 4b 03 [2] 5c 08 [2] 47 46 [2] 7a }

  condition:
    any of them
}