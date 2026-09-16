rule TTP_XOR_MULT_DOSStub_2926 {
  strings:
    $key_2926 = { 7d 4e [2] 09 56 [2] 4e 54 [2] 09 45 [2] 47 49 [2] 4b 43 [2] 5c 48 [2] 47 06 [2] 7a }

  condition:
    any of them
}