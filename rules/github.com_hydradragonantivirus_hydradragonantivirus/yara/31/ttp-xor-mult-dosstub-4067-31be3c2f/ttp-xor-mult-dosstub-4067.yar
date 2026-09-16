rule TTP_XOR_MULT_DOSStub_4067 {
  strings:
    $key_4067 = { 14 0f [2] 60 17 [2] 27 15 [2] 60 04 [2] 2e 08 [2] 22 02 [2] 35 09 [2] 2e 47 [2] 13 }

  condition:
    any of them
}