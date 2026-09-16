rule TTP_XOR_MULT_DOSStub_646f {
  strings:
    $key_646f = { 30 07 [2] 44 1f [2] 03 1d [2] 44 0c [2] 0a 00 [2] 06 0a [2] 11 01 [2] 0a 4f [2] 37 }

  condition:
    any of them
}