rule TTP_XOR_MULT_DOSStub_587f {
  strings:
    $key_587f = { 0c 17 [2] 78 0f [2] 3f 0d [2] 78 1c [2] 36 10 [2] 3a 1a [2] 2d 11 [2] 36 5f [2] 0b }

  condition:
    any of them
}