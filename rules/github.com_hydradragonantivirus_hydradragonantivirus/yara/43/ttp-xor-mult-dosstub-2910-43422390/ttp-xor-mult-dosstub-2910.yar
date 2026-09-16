rule TTP_XOR_MULT_DOSStub_2910 {
  strings:
    $key_2910 = { 7d 78 [2] 09 60 [2] 4e 62 [2] 09 73 [2] 47 7f [2] 4b 75 [2] 5c 7e [2] 47 30 [2] 7a }

  condition:
    any of them
}