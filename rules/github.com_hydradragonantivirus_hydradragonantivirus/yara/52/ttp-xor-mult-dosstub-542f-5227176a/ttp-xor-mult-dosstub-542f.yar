rule TTP_XOR_MULT_DOSStub_542f {
  strings:
    $key_542f = { 00 47 [2] 74 5f [2] 33 5d [2] 74 4c [2] 3a 40 [2] 36 4a [2] 21 41 [2] 3a 0f [2] 07 }

  condition:
    any of them
}