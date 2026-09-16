rule TTP_XOR_MULT_DOSStub_6a14 {
  strings:
    $key_6a14 = { 3e 7c [2] 4a 64 [2] 0d 66 [2] 4a 77 [2] 04 7b [2] 08 71 [2] 1f 7a [2] 04 34 [2] 39 }

  condition:
    any of them
}