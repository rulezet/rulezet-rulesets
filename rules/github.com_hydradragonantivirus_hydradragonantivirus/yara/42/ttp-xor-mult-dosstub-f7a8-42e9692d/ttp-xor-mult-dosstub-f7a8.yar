rule TTP_XOR_MULT_DOSStub_f7a8 {
  strings:
    $key_f7a8 = { a3 c0 [2] d7 d8 [2] 90 da [2] d7 cb [2] 99 c7 [2] 95 cd [2] 82 c6 [2] 99 88 [2] a4 }

  condition:
    any of them
}