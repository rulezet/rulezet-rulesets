rule TTP_XOR_MULT_DOSStub_5109 {
  strings:
    $key_5109 = { 05 61 [2] 71 79 [2] 36 7b [2] 71 6a [2] 3f 66 [2] 33 6c [2] 24 67 [2] 3f 29 [2] 02 }

  condition:
    any of them
}