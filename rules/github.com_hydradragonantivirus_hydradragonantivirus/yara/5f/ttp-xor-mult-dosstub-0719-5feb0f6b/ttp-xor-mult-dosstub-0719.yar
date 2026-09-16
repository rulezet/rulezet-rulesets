rule TTP_XOR_MULT_DOSStub_0719 {
  strings:
    $key_0719 = { 53 71 [2] 27 69 [2] 60 6b [2] 27 7a [2] 69 76 [2] 65 7c [2] 72 77 [2] 69 39 [2] 54 }

  condition:
    any of them
}