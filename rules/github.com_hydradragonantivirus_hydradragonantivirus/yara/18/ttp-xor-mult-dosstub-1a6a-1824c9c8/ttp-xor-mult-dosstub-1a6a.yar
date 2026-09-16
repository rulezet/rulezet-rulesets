rule TTP_XOR_MULT_DOSStub_1a6a {
  strings:
    $key_1a6a = { 4e 02 [2] 3a 1a [2] 7d 18 [2] 3a 09 [2] 74 05 [2] 78 0f [2] 6f 04 [2] 74 4a [2] 49 }

  condition:
    any of them
}