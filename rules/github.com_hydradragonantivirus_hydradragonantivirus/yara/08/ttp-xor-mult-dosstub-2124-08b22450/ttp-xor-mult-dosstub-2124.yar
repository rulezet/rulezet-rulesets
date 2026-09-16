rule TTP_XOR_MULT_DOSStub_2124 {
  strings:
    $key_2124 = { 75 4c [2] 01 54 [2] 46 56 [2] 01 47 [2] 4f 4b [2] 43 41 [2] 54 4a [2] 4f 04 [2] 72 }

  condition:
    any of them
}