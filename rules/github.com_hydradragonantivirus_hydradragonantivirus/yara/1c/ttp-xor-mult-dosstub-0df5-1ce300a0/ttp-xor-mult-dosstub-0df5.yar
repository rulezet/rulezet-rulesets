rule TTP_XOR_MULT_DOSStub_0df5 {
  strings:
    $key_0df5 = { 59 9d [2] 2d 85 [2] 6a 87 [2] 2d 96 [2] 63 9a [2] 6f 90 [2] 78 9b [2] 63 d5 [2] 5e }

  condition:
    any of them
}