rule TTP_XOR_MULT_DOSStub_5a28 {
  strings:
    $key_5a28 = { 0e 40 [2] 7a 58 [2] 3d 5a [2] 7a 4b [2] 34 47 [2] 38 4d [2] 2f 46 [2] 34 08 [2] 09 }

  condition:
    any of them
}