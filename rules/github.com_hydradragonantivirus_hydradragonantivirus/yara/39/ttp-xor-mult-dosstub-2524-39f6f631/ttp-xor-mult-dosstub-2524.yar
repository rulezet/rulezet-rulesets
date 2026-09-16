rule TTP_XOR_MULT_DOSStub_2524 {
  strings:
    $key_2524 = { 71 4c [2] 05 54 [2] 42 56 [2] 05 47 [2] 4b 4b [2] 47 41 [2] 50 4a [2] 4b 04 [2] 76 }

  condition:
    any of them
}