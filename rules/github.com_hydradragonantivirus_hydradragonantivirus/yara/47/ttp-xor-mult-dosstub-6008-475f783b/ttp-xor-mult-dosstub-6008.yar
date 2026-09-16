rule TTP_XOR_MULT_DOSStub_6008 {
  strings:
    $key_6008 = { 34 60 [2] 40 78 [2] 07 7a [2] 40 6b [2] 0e 67 [2] 02 6d [2] 15 66 [2] 0e 28 [2] 33 }

  condition:
    any of them
}