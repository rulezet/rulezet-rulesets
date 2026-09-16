rule TTP_XOR_MULT_DOSStub_6133 {
  strings:
    $key_6133 = { 35 5b [2] 41 43 [2] 06 41 [2] 41 50 [2] 0f 5c [2] 03 56 [2] 14 5d [2] 0f 13 [2] 32 }

  condition:
    any of them
}