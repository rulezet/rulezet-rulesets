rule TTP_XOR_MULT_DOSStub_5622 {
  strings:
    $key_5622 = { 02 4a [2] 76 52 [2] 31 50 [2] 76 41 [2] 38 4d [2] 34 47 [2] 23 4c [2] 38 02 [2] 05 }

  condition:
    any of them
}