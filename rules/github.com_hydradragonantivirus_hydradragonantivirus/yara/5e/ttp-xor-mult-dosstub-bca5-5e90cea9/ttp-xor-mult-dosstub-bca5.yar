rule TTP_XOR_MULT_DOSStub_bca5 {
  strings:
    $key_bca5 = { e8 cd [2] 9c d5 [2] db d7 [2] 9c c6 [2] d2 ca [2] de c0 [2] c9 cb [2] d2 85 [2] ef }

  condition:
    any of them
}