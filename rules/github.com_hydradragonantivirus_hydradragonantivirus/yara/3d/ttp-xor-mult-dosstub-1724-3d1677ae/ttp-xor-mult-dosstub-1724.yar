rule TTP_XOR_MULT_DOSStub_1724 {
  strings:
    $key_1724 = { 43 4c [2] 37 54 [2] 70 56 [2] 37 47 [2] 79 4b [2] 75 41 [2] 62 4a [2] 79 04 [2] 44 }

  condition:
    any of them
}