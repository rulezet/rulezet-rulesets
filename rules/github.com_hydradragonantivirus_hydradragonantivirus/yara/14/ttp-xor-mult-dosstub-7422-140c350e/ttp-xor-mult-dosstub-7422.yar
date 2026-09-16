rule TTP_XOR_MULT_DOSStub_7422 {
  strings:
    $key_7422 = { 20 4a [2] 54 52 [2] 13 50 [2] 54 41 [2] 1a 4d [2] 16 47 [2] 01 4c [2] 1a 02 [2] 27 }

  condition:
    any of them
}