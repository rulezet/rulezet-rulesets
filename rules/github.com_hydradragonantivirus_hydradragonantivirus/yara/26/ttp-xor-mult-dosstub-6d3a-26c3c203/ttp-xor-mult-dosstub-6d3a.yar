rule TTP_XOR_MULT_DOSStub_6d3a {
  strings:
    $key_6d3a = { 39 52 [2] 4d 4a [2] 0a 48 [2] 4d 59 [2] 03 55 [2] 0f 5f [2] 18 54 [2] 03 1a [2] 3e }

  condition:
    any of them
}