rule TTP_XOR_MULT_DOSStub_4162 {
  strings:
    $key_4162 = { 15 0a [2] 61 12 [2] 26 10 [2] 61 01 [2] 2f 0d [2] 23 07 [2] 34 0c [2] 2f 42 [2] 12 }

  condition:
    any of them
}