rule TTP_XOR_MULT_DOSStub_676f {
  strings:
    $key_676f = { 33 07 [2] 47 1f [2] 00 1d [2] 47 0c [2] 09 00 [2] 05 0a [2] 12 01 [2] 09 4f [2] 34 }

  condition:
    any of them
}