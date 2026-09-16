rule TTP_XOR_MULT_DOSStub_0814 {
  strings:
    $key_0814 = { 5c 7c [2] 28 64 [2] 6f 66 [2] 28 77 [2] 66 7b [2] 6a 71 [2] 7d 7a [2] 66 34 [2] 5b }

  condition:
    any of them
}