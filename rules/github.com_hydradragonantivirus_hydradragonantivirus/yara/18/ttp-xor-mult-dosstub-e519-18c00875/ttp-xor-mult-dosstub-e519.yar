rule TTP_XOR_MULT_DOSStub_e519 {
  strings:
    $key_e519 = { b1 71 [2] c5 69 [2] 82 6b [2] c5 7a [2] 8b 76 [2] 87 7c [2] 90 77 [2] 8b 39 [2] b6 }

  condition:
    any of them
}