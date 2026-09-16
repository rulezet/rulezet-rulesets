rule TTP_XOR_MULT_DOSStub_6c2f {
  strings:
    $key_6c2f = { 38 47 [2] 4c 5f [2] 0b 5d [2] 4c 4c [2] 02 40 [2] 0e 4a [2] 19 41 [2] 02 0f [2] 3f }

  condition:
    any of them
}