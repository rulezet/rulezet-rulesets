rule TTP_XOR_MULT_DOSStub_294a {
  strings:
    $key_294a = { 7d 22 [2] 09 3a [2] 4e 38 [2] 09 29 [2] 47 25 [2] 4b 2f [2] 5c 24 [2] 47 6a [2] 7a }

  condition:
    any of them
}