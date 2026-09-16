rule TTP_XOR_MULT_DOSStub_2129 {
  strings:
    $key_2129 = { 75 41 [2] 01 59 [2] 46 5b [2] 01 4a [2] 4f 46 [2] 43 4c [2] 54 47 [2] 4f 09 [2] 72 }

  condition:
    any of them
}