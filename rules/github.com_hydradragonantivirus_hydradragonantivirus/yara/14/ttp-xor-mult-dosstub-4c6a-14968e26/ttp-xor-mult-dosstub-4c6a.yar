rule TTP_XOR_MULT_DOSStub_4c6a {
  strings:
    $key_4c6a = { 18 02 [2] 6c 1a [2] 2b 18 [2] 6c 09 [2] 22 05 [2] 2e 0f [2] 39 04 [2] 22 4a [2] 1f }

  condition:
    any of them
}