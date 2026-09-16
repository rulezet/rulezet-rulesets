rule TTP_XOR_MULT_DOSStub_0116 {
  strings:
    $key_0116 = { 55 7e [2] 21 66 [2] 66 64 [2] 21 75 [2] 6f 79 [2] 63 73 [2] 74 78 [2] 6f 36 [2] 52 }

  condition:
    any of them
}