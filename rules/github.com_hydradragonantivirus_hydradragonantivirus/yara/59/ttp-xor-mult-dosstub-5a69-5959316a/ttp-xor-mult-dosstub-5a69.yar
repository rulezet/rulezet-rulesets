rule TTP_XOR_MULT_DOSStub_5a69 {
  strings:
    $key_5a69 = { 0e 01 [2] 7a 19 [2] 3d 1b [2] 7a 0a [2] 34 06 [2] 38 0c [2] 2f 07 [2] 34 49 [2] 09 }

  condition:
    any of them
}