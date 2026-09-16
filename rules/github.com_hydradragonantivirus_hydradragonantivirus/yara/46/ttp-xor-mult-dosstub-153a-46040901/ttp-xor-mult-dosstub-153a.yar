rule TTP_XOR_MULT_DOSStub_153a {
  strings:
    $key_153a = { 41 52 [2] 35 4a [2] 72 48 [2] 35 59 [2] 7b 55 [2] 77 5f [2] 60 54 [2] 7b 1a [2] 46 }

  condition:
    any of them
}