rule TTP_XOR_MULT_DOSStub_200a {
  strings:
    $key_200a = { 74 62 [2] 00 7a [2] 47 78 [2] 00 69 [2] 4e 65 [2] 42 6f [2] 55 64 [2] 4e 2a [2] 73 }

  condition:
    any of them
}