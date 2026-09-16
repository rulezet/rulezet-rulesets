rule TTP_XOR_MULT_DOSStub_2a6a {
  strings:
    $key_2a6a = { 7e 02 [2] 0a 1a [2] 4d 18 [2] 0a 09 [2] 44 05 [2] 48 0f [2] 5f 04 [2] 44 4a [2] 79 }

  condition:
    any of them
}