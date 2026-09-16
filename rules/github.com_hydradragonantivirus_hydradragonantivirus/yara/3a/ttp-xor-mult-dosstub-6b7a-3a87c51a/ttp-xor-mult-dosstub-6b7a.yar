rule TTP_XOR_MULT_DOSStub_6b7a {
  strings:
    $key_6b7a = { 3f 12 [2] 4b 0a [2] 0c 08 [2] 4b 19 [2] 05 15 [2] 09 1f [2] 1e 14 [2] 05 5a [2] 38 }

  condition:
    any of them
}