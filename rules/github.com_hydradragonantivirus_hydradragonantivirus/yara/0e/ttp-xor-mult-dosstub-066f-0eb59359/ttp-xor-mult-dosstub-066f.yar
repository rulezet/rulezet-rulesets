rule TTP_XOR_MULT_DOSStub_066f {
  strings:
    $key_066f = { 52 07 [2] 26 1f [2] 61 1d [2] 26 0c [2] 68 00 [2] 64 0a [2] 73 01 [2] 68 4f [2] 55 }

  condition:
    any of them
}