rule TTP_XOR_MULT_DOSStub_186f {
  strings:
    $key_186f = { 4c 07 [2] 38 1f [2] 7f 1d [2] 38 0c [2] 76 00 [2] 7a 0a [2] 6d 01 [2] 76 4f [2] 4b }

  condition:
    any of them
}