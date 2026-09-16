rule TTP_XOR_MULT_DOSStub_526a {
  strings:
    $key_526a = { 06 02 [2] 72 1a [2] 35 18 [2] 72 09 [2] 3c 05 [2] 30 0f [2] 27 04 [2] 3c 4a [2] 01 }

  condition:
    any of them
}