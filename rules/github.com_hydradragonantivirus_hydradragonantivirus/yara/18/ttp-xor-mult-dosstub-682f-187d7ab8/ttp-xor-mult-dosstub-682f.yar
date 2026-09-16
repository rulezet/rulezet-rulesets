rule TTP_XOR_MULT_DOSStub_682f {
  strings:
    $key_682f = { 3c 47 [2] 48 5f [2] 0f 5d [2] 48 4c [2] 06 40 [2] 0a 4a [2] 1d 41 [2] 06 0f [2] 3b }

  condition:
    any of them
}