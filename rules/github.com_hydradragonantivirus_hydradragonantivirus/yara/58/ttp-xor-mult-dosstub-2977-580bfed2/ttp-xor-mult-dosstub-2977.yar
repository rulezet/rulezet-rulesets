rule TTP_XOR_MULT_DOSStub_2977 {
  strings:
    $key_2977 = { 7d 1f [2] 09 07 [2] 4e 05 [2] 09 14 [2] 47 18 [2] 4b 12 [2] 5c 19 [2] 47 57 [2] 7a }

  condition:
    any of them
}