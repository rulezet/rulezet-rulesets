rule TTP_XOR_MULT_DOSStub_0616 {
  strings:
    $key_0616 = { 52 7e [2] 26 66 [2] 61 64 [2] 26 75 [2] 68 79 [2] 64 73 [2] 73 78 [2] 68 36 [2] 55 }

  condition:
    any of them
}