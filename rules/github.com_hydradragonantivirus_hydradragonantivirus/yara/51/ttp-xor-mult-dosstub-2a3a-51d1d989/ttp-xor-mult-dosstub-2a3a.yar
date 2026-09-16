rule TTP_XOR_MULT_DOSStub_2a3a {
  strings:
    $key_2a3a = { 7e 52 [2] 0a 4a [2] 4d 48 [2] 0a 59 [2] 44 55 [2] 48 5f [2] 5f 54 [2] 44 1a [2] 79 }

  condition:
    any of them
}