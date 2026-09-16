rule TTP_XOR_MULT_DOSStub_4a2f {
  strings:
    $key_4a2f = { 1e 47 [2] 6a 5f [2] 2d 5d [2] 6a 4c [2] 24 40 [2] 28 4a [2] 3f 41 [2] 24 0f [2] 19 }

  condition:
    any of them
}