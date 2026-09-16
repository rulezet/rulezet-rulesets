rule TTP_XOR_MULT_DOSStub_1633 {
  strings:
    $key_1633 = { 42 5b [2] 36 43 [2] 71 41 [2] 36 50 [2] 78 5c [2] 74 56 [2] 63 5d [2] 78 13 [2] 45 }

  condition:
    any of them
}