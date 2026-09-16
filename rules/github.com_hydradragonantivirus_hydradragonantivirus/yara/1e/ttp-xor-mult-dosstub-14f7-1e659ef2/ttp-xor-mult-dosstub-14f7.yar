rule TTP_XOR_MULT_DOSStub_14f7 {
  strings:
    $key_14f7 = { 40 9f [2] 34 87 [2] 73 85 [2] 34 94 [2] 7a 98 [2] 76 92 [2] 61 99 [2] 7a d7 [2] 47 }

  condition:
    any of them
}