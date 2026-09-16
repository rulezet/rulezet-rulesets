rule TTP_XOR_MULT_DOSStub_1629 {
  strings:
    $key_1629 = { 42 41 [2] 36 59 [2] 71 5b [2] 36 4a [2] 78 46 [2] 74 4c [2] 63 47 [2] 78 09 [2] 45 }

  condition:
    any of them
}