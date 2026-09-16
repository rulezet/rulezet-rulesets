rule TTP_XOR_MULT_DOSStub_5033 {
  strings:
    $key_5033 = { 04 5b [2] 70 43 [2] 37 41 [2] 70 50 [2] 3e 5c [2] 32 56 [2] 25 5d [2] 3e 13 [2] 03 }

  condition:
    any of them
}