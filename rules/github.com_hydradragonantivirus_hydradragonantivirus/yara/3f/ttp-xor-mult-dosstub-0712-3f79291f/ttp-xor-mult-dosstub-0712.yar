rule TTP_XOR_MULT_DOSStub_0712 {
  strings:
    $key_0712 = { 53 7a [2] 27 62 [2] 60 60 [2] 27 71 [2] 69 7d [2] 65 77 [2] 72 7c [2] 69 32 [2] 54 }

  condition:
    any of them
}