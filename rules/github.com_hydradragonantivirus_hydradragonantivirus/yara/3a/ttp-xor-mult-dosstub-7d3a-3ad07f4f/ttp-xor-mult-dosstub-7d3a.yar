rule TTP_XOR_MULT_DOSStub_7d3a {
  strings:
    $key_7d3a = { 29 52 [2] 5d 4a [2] 1a 48 [2] 5d 59 [2] 13 55 [2] 1f 5f [2] 08 54 [2] 13 1a [2] 2e }

  condition:
    any of them
}