rule TTP_XOR_MULT_DOSStub_636a {
  strings:
    $key_636a = { 37 02 [2] 43 1a [2] 04 18 [2] 43 09 [2] 0d 05 [2] 01 0f [2] 16 04 [2] 0d 4a [2] 30 }

  condition:
    any of them
}