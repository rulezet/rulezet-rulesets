rule TTP_XOR_MULT_DOSStub_6d14 {
  strings:
    $key_6d14 = { 39 7c [2] 4d 64 [2] 0a 66 [2] 4d 77 [2] 03 7b [2] 0f 71 [2] 18 7a [2] 03 34 [2] 3e }

  condition:
    any of them
}