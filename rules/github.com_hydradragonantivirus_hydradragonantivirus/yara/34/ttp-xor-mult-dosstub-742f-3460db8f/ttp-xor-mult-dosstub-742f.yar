rule TTP_XOR_MULT_DOSStub_742f {
  strings:
    $key_742f = { 20 47 [2] 54 5f [2] 13 5d [2] 54 4c [2] 1a 40 [2] 16 4a [2] 01 41 [2] 1a 0f [2] 27 }

  condition:
    any of them
}