rule TTP_XOR_MULT_DOSStub_2970 {
  strings:
    $key_2970 = { 7d 18 [2] 09 00 [2] 4e 02 [2] 09 13 [2] 47 1f [2] 4b 15 [2] 5c 1e [2] 47 50 [2] 7a }

  condition:
    any of them
}