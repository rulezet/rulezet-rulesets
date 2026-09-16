rule TTP_XOR_MULT_DOSStub_6a4a {
  strings:
    $key_6a4a = { 3e 22 [2] 4a 3a [2] 0d 38 [2] 4a 29 [2] 04 25 [2] 08 2f [2] 1f 24 [2] 04 6a [2] 39 }

  condition:
    any of them
}