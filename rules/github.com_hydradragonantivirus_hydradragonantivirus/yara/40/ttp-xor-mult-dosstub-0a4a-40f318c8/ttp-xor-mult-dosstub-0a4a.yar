rule TTP_XOR_MULT_DOSStub_0a4a {
  strings:
    $key_0a4a = { 5e 22 [2] 2a 3a [2] 6d 38 [2] 2a 29 [2] 64 25 [2] 68 2f [2] 7f 24 [2] 64 6a [2] 59 }

  condition:
    any of them
}