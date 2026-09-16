rule TTP_XOR_MULT_DOSStub_4622 {
  strings:
    $key_4622 = { 12 4a [2] 66 52 [2] 21 50 [2] 66 41 [2] 28 4d [2] 24 47 [2] 33 4c [2] 28 02 [2] 15 }

  condition:
    any of them
}