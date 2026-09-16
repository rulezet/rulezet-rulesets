rule TTP_XOR_MULT_DOSStub_1610 {
  strings:
    $key_1610 = { 42 78 [2] 36 60 [2] 71 62 [2] 36 73 [2] 78 7f [2] 74 75 [2] 63 7e [2] 78 30 [2] 45 }

  condition:
    any of them
}