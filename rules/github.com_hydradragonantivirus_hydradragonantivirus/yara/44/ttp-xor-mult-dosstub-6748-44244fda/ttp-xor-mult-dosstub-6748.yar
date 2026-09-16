rule TTP_XOR_MULT_DOSStub_6748 {
  strings:
    $key_6748 = { 33 20 [2] 47 38 [2] 00 3a [2] 47 2b [2] 09 27 [2] 05 2d [2] 12 26 [2] 09 68 [2] 34 }

  condition:
    any of them
}