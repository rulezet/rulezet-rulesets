rule TTP_XOR_MULT_DOSStub_482f {
  strings:
    $key_482f = { 1c 47 [2] 68 5f [2] 2f 5d [2] 68 4c [2] 26 40 [2] 2a 4a [2] 3d 41 [2] 26 0f [2] 1b }

  condition:
    any of them
}