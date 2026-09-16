rule TTP_XOR_MULT_DOSStub_191a {
  strings:
    $key_191a = { 4d 72 [2] 39 6a [2] 7e 68 [2] 39 79 [2] 77 75 [2] 7b 7f [2] 6c 74 [2] 77 3a [2] 4a }

  condition:
    any of them
}