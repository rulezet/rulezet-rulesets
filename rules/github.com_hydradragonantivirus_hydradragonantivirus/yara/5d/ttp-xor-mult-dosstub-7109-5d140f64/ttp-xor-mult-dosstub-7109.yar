rule TTP_XOR_MULT_DOSStub_7109 {
  strings:
    $key_7109 = { 25 61 [2] 51 79 [2] 16 7b [2] 51 6a [2] 1f 66 [2] 13 6c [2] 04 67 [2] 1f 29 [2] 22 }

  condition:
    any of them
}