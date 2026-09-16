rule TTP_XOR_MULT_DOSStub_0b3a {
  strings:
    $key_0b3a = { 5f 52 [2] 2b 4a [2] 6c 48 [2] 2b 59 [2] 65 55 [2] 69 5f [2] 7e 54 [2] 65 1a [2] 58 }

  condition:
    any of them
}