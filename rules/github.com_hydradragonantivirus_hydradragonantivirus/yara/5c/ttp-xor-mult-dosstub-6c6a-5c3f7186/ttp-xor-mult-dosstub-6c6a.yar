rule TTP_XOR_MULT_DOSStub_6c6a {
  strings:
    $key_6c6a = { 38 02 [2] 4c 1a [2] 0b 18 [2] 4c 09 [2] 02 05 [2] 0e 0f [2] 19 04 [2] 02 4a [2] 3f }

  condition:
    any of them
}