rule TTP_XOR_MULT_DOSStub_37a8 {
  strings:
    $key_37a8 = { 63 c0 [2] 17 d8 [2] 50 da [2] 17 cb [2] 59 c7 [2] 55 cd [2] 42 c6 [2] 59 88 [2] 64 }

  condition:
    any of them
}