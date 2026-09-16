rule TTP_XOR_MULT_DOSStub_2504 {
  strings:
    $key_2504 = { 71 6c [2] 05 74 [2] 42 76 [2] 05 67 [2] 4b 6b [2] 47 61 [2] 50 6a [2] 4b 24 [2] 76 }

  condition:
    any of them
}