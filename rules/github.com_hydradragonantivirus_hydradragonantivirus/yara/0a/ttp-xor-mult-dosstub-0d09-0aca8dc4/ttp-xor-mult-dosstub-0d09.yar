rule TTP_XOR_MULT_DOSStub_0d09 {
  strings:
    $key_0d09 = { 59 61 [2] 2d 79 [2] 6a 7b [2] 2d 6a [2] 63 66 [2] 6f 6c [2] 78 67 [2] 63 29 [2] 5e }

  condition:
    any of them
}