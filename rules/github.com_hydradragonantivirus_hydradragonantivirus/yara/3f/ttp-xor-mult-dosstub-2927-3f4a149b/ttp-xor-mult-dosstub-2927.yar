rule TTP_XOR_MULT_DOSStub_2927 {
  strings:
    $key_2927 = { 7d 4f [2] 09 57 [2] 4e 55 [2] 09 44 [2] 47 48 [2] 4b 42 [2] 5c 49 [2] 47 07 [2] 7a }

  condition:
    any of them
}