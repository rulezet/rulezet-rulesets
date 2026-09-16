rule TTP_XOR_MULT_DOSStub_e819 {
  strings:
    $key_e819 = { bc 71 [2] c8 69 [2] 8f 6b [2] c8 7a [2] 86 76 [2] 8a 7c [2] 9d 77 [2] 86 39 [2] bb }

  condition:
    any of them
}