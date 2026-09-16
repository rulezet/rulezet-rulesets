rule TTP_XOR_MULT_DOSStub_7919 {
  strings:
    $key_7919 = { 2d 71 [2] 59 69 [2] 1e 6b [2] 59 7a [2] 17 76 [2] 1b 7c [2] 0c 77 [2] 17 39 [2] 2a }

  condition:
    any of them
}