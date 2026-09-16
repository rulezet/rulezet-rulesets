rule TTP_XOR_MULT_DOSStub_e814 {
  strings:
    $key_e814 = { bc 7c [2] c8 64 [2] 8f 66 [2] c8 77 [2] 86 7b [2] 8a 71 [2] 9d 7a [2] 86 34 [2] bb }

  condition:
    any of them
}