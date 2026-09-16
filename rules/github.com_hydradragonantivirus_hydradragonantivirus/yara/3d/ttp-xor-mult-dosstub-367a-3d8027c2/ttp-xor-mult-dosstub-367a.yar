rule TTP_XOR_MULT_DOSStub_367a {
  strings:
    $key_367a = { 62 12 [2] 16 0a [2] 51 08 [2] 16 19 [2] 58 15 [2] 54 1f [2] 43 14 [2] 58 5a [2] 65 }

  condition:
    any of them
}