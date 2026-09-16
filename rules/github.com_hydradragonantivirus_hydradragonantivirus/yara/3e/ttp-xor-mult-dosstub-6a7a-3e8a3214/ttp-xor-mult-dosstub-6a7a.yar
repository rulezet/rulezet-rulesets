rule TTP_XOR_MULT_DOSStub_6a7a {
  strings:
    $key_6a7a = { 3e 12 [2] 4a 0a [2] 0d 08 [2] 4a 19 [2] 04 15 [2] 08 1f [2] 1f 14 [2] 04 5a [2] 39 }

  condition:
    any of them
}