rule TTP_XOR_MULT_DOSStub_177f {
  strings:
    $key_177f = { 43 17 [2] 37 0f [2] 70 0d [2] 37 1c [2] 79 10 [2] 75 1a [2] 62 11 [2] 79 5f [2] 44 }

  condition:
    any of them
}