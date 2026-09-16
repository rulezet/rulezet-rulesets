rule TTP_XOR_MULT_DOSStub_2930 {
  strings:
    $key_2930 = { 7d 58 [2] 09 40 [2] 4e 42 [2] 09 53 [2] 47 5f [2] 4b 55 [2] 5c 5e [2] 47 10 [2] 7a }

  condition:
    any of them
}