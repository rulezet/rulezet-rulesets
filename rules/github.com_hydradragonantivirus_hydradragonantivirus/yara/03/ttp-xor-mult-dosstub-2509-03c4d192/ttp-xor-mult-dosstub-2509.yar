rule TTP_XOR_MULT_DOSStub_2509 {
  strings:
    $key_2509 = { 71 61 [2] 05 79 [2] 42 7b [2] 05 6a [2] 4b 66 [2] 47 6c [2] 50 67 [2] 4b 29 [2] 76 }

  condition:
    any of them
}