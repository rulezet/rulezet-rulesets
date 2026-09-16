rule TTP_XOR_MULT_DOSStub_713a {
  strings:
    $key_713a = { 25 52 [2] 51 4a [2] 16 48 [2] 51 59 [2] 1f 55 [2] 13 5f [2] 04 54 [2] 1f 1a [2] 22 }

  condition:
    any of them
}