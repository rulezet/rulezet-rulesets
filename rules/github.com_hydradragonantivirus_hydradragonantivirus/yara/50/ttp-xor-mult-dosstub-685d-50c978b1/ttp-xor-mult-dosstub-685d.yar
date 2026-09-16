rule TTP_XOR_MULT_DOSStub_685d {
  strings:
    $key_685d = { 3c 35 [2] 48 2d [2] 0f 2f [2] 48 3e [2] 06 32 [2] 0a 38 [2] 1d 33 [2] 06 7d [2] 3b }

  condition:
    any of them
}