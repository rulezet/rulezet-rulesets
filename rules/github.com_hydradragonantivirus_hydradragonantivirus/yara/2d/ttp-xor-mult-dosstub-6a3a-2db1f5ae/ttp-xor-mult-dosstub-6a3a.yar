rule TTP_XOR_MULT_DOSStub_6a3a {
  strings:
    $key_6a3a = { 3e 52 [2] 4a 4a [2] 0d 48 [2] 4a 59 [2] 04 55 [2] 08 5f [2] 1f 54 [2] 04 1a [2] 39 }

  condition:
    any of them
}