rule TTP_XOR_MULT_DOSStub_5a2f {
  strings:
    $key_5a2f = { 0e 47 [2] 7a 5f [2] 3d 5d [2] 7a 4c [2] 34 40 [2] 38 4a [2] 2f 41 [2] 34 0f [2] 09 }

  condition:
    any of them
}