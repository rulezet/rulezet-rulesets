rule TTP_XOR_MULT_DOSStub_176a {
  strings:
    $key_176a = { 43 02 [2] 37 1a [2] 70 18 [2] 37 09 [2] 79 05 [2] 75 0f [2] 62 04 [2] 79 4a [2] 44 }

  condition:
    any of them
}