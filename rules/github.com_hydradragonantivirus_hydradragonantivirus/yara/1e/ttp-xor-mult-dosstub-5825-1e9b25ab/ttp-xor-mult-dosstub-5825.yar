rule TTP_XOR_MULT_DOSStub_5825 {
  strings:
    $key_5825 = { 0c 4d [2] 78 55 [2] 3f 57 [2] 78 46 [2] 36 4a [2] 3a 40 [2] 2d 4b [2] 36 05 [2] 0b }

  condition:
    any of them
}