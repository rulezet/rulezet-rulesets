rule TTP_XOR_MULT_DOSStub_453a {
  strings:
    $key_453a = { 11 52 [2] 65 4a [2] 22 48 [2] 65 59 [2] 2b 55 [2] 27 5f [2] 30 54 [2] 2b 1a [2] 16 }

  condition:
    any of them
}