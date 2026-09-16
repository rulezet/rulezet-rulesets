rule TTP_XOR_MULT_DOSStub_3553 {
  strings:
    $key_3553 = { 61 3b [2] 15 23 [2] 52 21 [2] 15 30 [2] 5b 3c [2] 57 36 [2] 40 3d [2] 5b 73 [2] 66 }

  condition:
    any of them
}