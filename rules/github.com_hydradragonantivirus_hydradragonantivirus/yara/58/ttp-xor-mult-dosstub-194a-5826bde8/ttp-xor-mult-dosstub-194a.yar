rule TTP_XOR_MULT_DOSStub_194a {
  strings:
    $key_194a = { 4d 22 [2] 39 3a [2] 7e 38 [2] 39 29 [2] 77 25 [2] 7b 2f [2] 6c 24 [2] 77 6a [2] 4a }

  condition:
    any of them
}