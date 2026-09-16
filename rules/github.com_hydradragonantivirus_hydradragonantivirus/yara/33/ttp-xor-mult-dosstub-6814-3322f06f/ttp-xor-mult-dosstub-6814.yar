rule TTP_XOR_MULT_DOSStub_6814 {
  strings:
    $key_6814 = { 3c 7c [2] 48 64 [2] 0f 66 [2] 48 77 [2] 06 7b [2] 0a 71 [2] 1d 7a [2] 06 34 [2] 3b }

  condition:
    any of them
}