rule TTP_XOR_MULT_DOSStub_30a8 {
  strings:
    $key_30a8 = { 64 c0 [2] 10 d8 [2] 57 da [2] 10 cb [2] 5e c7 [2] 52 cd [2] 45 c6 [2] 5e 88 [2] 63 }

  condition:
    any of them
}