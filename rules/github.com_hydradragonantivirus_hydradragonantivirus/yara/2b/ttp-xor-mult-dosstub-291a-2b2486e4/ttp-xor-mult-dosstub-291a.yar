rule TTP_XOR_MULT_DOSStub_291a {
  strings:
    $key_291a = { 7d 72 [2] 09 6a [2] 4e 68 [2] 09 79 [2] 47 75 [2] 4b 7f [2] 5c 74 [2] 47 3a [2] 7a }

  condition:
    any of them
}