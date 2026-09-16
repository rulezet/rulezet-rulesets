rule TTP_XOR_MULT_DOSStub_796a {
  strings:
    $key_796a = { 2d 02 [2] 59 1a [2] 1e 18 [2] 59 09 [2] 17 05 [2] 1b 0f [2] 0c 04 [2] 17 4a [2] 2a }

  condition:
    any of them
}