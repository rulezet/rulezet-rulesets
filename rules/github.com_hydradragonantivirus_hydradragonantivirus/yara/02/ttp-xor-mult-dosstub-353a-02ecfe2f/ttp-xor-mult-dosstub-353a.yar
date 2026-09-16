rule TTP_XOR_MULT_DOSStub_353a {
  strings:
    $key_353a = { 61 52 [2] 15 4a [2] 52 48 [2] 15 59 [2] 5b 55 [2] 57 5f [2] 40 54 [2] 5b 1a [2] 66 }

  condition:
    any of them
}