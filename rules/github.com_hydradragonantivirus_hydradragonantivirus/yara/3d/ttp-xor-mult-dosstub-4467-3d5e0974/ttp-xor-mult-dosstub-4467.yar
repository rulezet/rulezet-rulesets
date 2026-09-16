rule TTP_XOR_MULT_DOSStub_4467 {
  strings:
    $key_4467 = { 10 0f [2] 64 17 [2] 23 15 [2] 64 04 [2] 2a 08 [2] 26 02 [2] 31 09 [2] 2a 47 [2] 17 }

  condition:
    any of them
}