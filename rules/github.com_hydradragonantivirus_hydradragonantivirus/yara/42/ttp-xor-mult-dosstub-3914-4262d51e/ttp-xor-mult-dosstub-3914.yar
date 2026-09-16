rule TTP_XOR_MULT_DOSStub_3914 {
  strings:
    $key_3914 = { 6d 7c [2] 19 64 [2] 5e 66 [2] 19 77 [2] 57 7b [2] 5b 71 [2] 4c 7a [2] 57 34 [2] 6a }

  condition:
    any of them
}