rule TTP_XOR_MULT_DOSStub_013a {
  strings:
    $key_013a = { 55 52 [2] 21 4a [2] 66 48 [2] 21 59 [2] 6f 55 [2] 63 5f [2] 74 54 [2] 6f 1a [2] 52 }

  condition:
    any of them
}