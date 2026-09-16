rule TTP_XOR_MULT_DOSStub_5824 {
  strings:
    $key_5824 = { 0c 4c [2] 78 54 [2] 3f 56 [2] 78 47 [2] 36 4b [2] 3a 41 [2] 2d 4a [2] 36 04 [2] 0b }

  condition:
    any of them
}