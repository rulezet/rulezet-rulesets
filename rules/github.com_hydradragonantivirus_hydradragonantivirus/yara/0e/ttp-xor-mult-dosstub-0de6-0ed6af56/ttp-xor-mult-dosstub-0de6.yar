rule TTP_XOR_MULT_DOSStub_0de6 {
  strings:
    $key_0de6 = { 59 8e [2] 2d 96 [2] 6a 94 [2] 2d 85 [2] 63 89 [2] 6f 83 [2] 78 88 [2] 63 c6 [2] 5e }

  condition:
    any of them
}