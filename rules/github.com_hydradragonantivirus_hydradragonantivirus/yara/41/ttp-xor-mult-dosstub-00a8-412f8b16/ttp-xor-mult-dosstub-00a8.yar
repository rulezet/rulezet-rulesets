rule TTP_XOR_MULT_DOSStub_00a8 {
  strings:
    $key_00a8 = { 54 c0 [2] 20 d8 [2] 67 da [2] 20 cb [2] 6e c7 [2] 62 cd [2] 75 c6 [2] 6e 88 [2] 53 }

  condition:
    any of them
}