rule TTP_XOR_MULT_DOSStub_0014 {
  strings:
    $key_0014 = { 54 7c [2] 20 64 [2] 67 66 [2] 20 77 [2] 6e 7b [2] 62 71 [2] 75 7a [2] 6e 34 [2] 53 }

  condition:
    any of them
}