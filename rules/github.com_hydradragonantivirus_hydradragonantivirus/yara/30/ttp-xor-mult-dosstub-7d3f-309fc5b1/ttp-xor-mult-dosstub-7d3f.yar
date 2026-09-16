rule TTP_XOR_MULT_DOSStub_7d3f {
  strings:
    $key_7d3f = { 29 57 [2] 5d 4f [2] 1a 4d [2] 5d 5c [2] 13 50 [2] 1f 5a [2] 08 51 [2] 13 1f [2] 2e }

  condition:
    any of them
}