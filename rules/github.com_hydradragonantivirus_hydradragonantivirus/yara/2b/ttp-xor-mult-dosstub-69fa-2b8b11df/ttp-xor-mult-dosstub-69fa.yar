rule TTP_XOR_MULT_DOSStub_69fa {
  strings:
    $key_69fa = { 3d 92 [2] 49 8a [2] 0e 88 [2] 49 99 [2] 07 95 [2] 0b 9f [2] 1c 94 [2] 07 da [2] 3a }

  condition:
    any of them
}