rule TTP_XOR_MULT_DOSStub_073a {
  strings:
    $key_073a = { 53 52 [2] 27 4a [2] 60 48 [2] 27 59 [2] 69 55 [2] 65 5f [2] 72 54 [2] 69 1a [2] 54 }

  condition:
    any of them
}