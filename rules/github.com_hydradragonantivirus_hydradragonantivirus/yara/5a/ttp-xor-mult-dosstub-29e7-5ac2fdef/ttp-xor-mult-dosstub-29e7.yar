rule TTP_XOR_MULT_DOSStub_29e7 {
  strings:
    $key_29e7 = { 7d 8f [2] 09 97 [2] 4e 95 [2] 09 84 [2] 47 88 [2] 4b 82 [2] 5c 89 [2] 47 c7 [2] 7a }

  condition:
    any of them
}