rule TTP_XOR_MULT_DOSStub_172f {
  strings:
    $key_172f = { 43 47 [2] 37 5f [2] 70 5d [2] 37 4c [2] 79 40 [2] 75 4a [2] 62 41 [2] 79 0f [2] 44 }

  condition:
    any of them
}