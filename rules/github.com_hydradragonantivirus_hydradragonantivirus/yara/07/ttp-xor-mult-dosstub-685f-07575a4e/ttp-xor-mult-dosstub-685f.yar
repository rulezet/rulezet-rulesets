rule TTP_XOR_MULT_DOSStub_685f {
  strings:
    $key_685f = { 3c 37 [2] 48 2f [2] 0f 2d [2] 48 3c [2] 06 30 [2] 0a 3a [2] 1d 31 [2] 06 7f [2] 3b }

  condition:
    any of them
}