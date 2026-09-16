rule TTP_XOR_MULT_DOSStub_186a {
  strings:
    $key_186a = { 4c 02 [2] 38 1a [2] 7f 18 [2] 38 09 [2] 76 05 [2] 7a 0f [2] 6d 04 [2] 76 4a [2] 4b }

  condition:
    any of them
}