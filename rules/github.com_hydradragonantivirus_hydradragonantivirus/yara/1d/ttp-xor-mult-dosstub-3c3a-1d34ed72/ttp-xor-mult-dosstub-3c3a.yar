rule TTP_XOR_MULT_DOSStub_3c3a {
  strings:
    $key_3c3a = { 68 52 [2] 1c 4a [2] 5b 48 [2] 1c 59 [2] 52 55 [2] 5e 5f [2] 49 54 [2] 52 1a [2] 6f }

  condition:
    any of them
}