rule TTP_XOR_MULT_DOSStub_2931 {
  strings:
    $key_2931 = { 7d 59 [2] 09 41 [2] 4e 43 [2] 09 52 [2] 47 5e [2] 4b 54 [2] 5c 5f [2] 47 11 [2] 7a }

  condition:
    any of them
}