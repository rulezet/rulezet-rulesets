rule TTP_XOR_MULT_DOSStub_2956 {
  strings:
    $key_2956 = { 7d 3e [2] 09 26 [2] 4e 24 [2] 09 35 [2] 47 39 [2] 4b 33 [2] 5c 38 [2] 47 76 [2] 7a }

  condition:
    any of them
}