rule TTP_XOR_MULT_DOSStub_0d3a {
  strings:
    $key_0d3a = { 59 52 [2] 2d 4a [2] 6a 48 [2] 2d 59 [2] 63 55 [2] 6f 5f [2] 78 54 [2] 63 1a [2] 5e }

  condition:
    any of them
}