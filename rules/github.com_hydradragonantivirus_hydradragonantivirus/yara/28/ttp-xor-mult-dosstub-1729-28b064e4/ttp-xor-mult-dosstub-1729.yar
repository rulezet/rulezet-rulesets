rule TTP_XOR_MULT_DOSStub_1729 {
  strings:
    $key_1729 = { 43 41 [2] 37 59 [2] 70 5b [2] 37 4a [2] 79 46 [2] 75 4c [2] 62 47 [2] 79 09 [2] 44 }

  condition:
    any of them
}