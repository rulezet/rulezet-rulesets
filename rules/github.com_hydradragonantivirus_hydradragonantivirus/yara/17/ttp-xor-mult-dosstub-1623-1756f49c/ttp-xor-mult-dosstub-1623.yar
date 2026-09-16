rule TTP_XOR_MULT_DOSStub_1623 {
  strings:
    $key_1623 = { 42 4b [2] 36 53 [2] 71 51 [2] 36 40 [2] 78 4c [2] 74 46 [2] 63 4d [2] 78 03 [2] 45 }

  condition:
    any of them
}