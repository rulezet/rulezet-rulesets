rule TTP_XOR_MULT_DOSStub_3d3a {
  strings:
    $key_3d3a = { 69 52 [2] 1d 4a [2] 5a 48 [2] 1d 59 [2] 53 55 [2] 5f 5f [2] 48 54 [2] 53 1a [2] 6e }

  condition:
    any of them
}