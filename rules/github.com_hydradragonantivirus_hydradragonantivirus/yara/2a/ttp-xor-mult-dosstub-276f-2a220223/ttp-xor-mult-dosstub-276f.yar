rule TTP_XOR_MULT_DOSStub_276f {
  strings:
    $key_276f = { 73 07 [2] 07 1f [2] 40 1d [2] 07 0c [2] 49 00 [2] 45 0a [2] 52 01 [2] 49 4f [2] 74 }

  condition:
    any of them
}