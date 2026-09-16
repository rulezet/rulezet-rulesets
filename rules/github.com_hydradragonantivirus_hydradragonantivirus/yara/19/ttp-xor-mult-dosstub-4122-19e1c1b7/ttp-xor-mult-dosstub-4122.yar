rule TTP_XOR_MULT_DOSStub_4122 {
  strings:
    $key_4122 = { 15 4a [2] 61 52 [2] 26 50 [2] 61 41 [2] 2f 4d [2] 23 47 [2] 34 4c [2] 2f 02 [2] 12 }

  condition:
    any of them
}