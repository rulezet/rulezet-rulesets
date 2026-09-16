rule TTP_XOR_MULT_DOSStub_f0a8 {
  strings:
    $key_f0a8 = { a4 c0 [2] d0 d8 [2] 97 da [2] d0 cb [2] 9e c7 [2] 92 cd [2] 85 c6 [2] 9e 88 [2] a3 }

  condition:
    any of them
}