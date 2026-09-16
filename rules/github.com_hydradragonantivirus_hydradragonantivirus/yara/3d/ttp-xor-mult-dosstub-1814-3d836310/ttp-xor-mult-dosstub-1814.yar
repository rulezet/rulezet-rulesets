rule TTP_XOR_MULT_DOSStub_1814 {
  strings:
    $key_1814 = { 4c 7c [2] 38 64 [2] 7f 66 [2] 38 77 [2] 76 7b [2] 7a 71 [2] 6d 7a [2] 76 34 [2] 4b }

  condition:
    any of them
}