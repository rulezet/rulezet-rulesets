rule TTP_XOR_MULT_DOSStub_0b7a {
  strings:
    $key_0b7a = { 5f 12 [2] 2b 0a [2] 6c 08 [2] 2b 19 [2] 65 15 [2] 69 1f [2] 7e 14 [2] 65 5a [2] 58 }

  condition:
    any of them
}