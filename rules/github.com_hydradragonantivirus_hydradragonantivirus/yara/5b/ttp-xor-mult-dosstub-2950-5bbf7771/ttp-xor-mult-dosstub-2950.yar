rule TTP_XOR_MULT_DOSStub_2950 {
  strings:
    $key_2950 = { 7d 38 [2] 09 20 [2] 4e 22 [2] 09 33 [2] 47 3f [2] 4b 35 [2] 5c 3e [2] 47 70 [2] 7a }

  condition:
    any of them
}