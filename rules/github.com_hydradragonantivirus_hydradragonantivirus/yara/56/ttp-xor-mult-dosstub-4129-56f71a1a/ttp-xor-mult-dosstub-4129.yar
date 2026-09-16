rule TTP_XOR_MULT_DOSStub_4129 {
  strings:
    $key_4129 = { 15 41 [2] 61 59 [2] 26 5b [2] 61 4a [2] 2f 46 [2] 23 4c [2] 34 47 [2] 2f 09 [2] 12 }

  condition:
    any of them
}