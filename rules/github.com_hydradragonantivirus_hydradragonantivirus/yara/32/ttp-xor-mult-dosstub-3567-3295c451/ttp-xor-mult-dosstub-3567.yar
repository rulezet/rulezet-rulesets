rule TTP_XOR_MULT_DOSStub_3567 {
  strings:
    $key_3567 = { 61 0f [2] 15 17 [2] 52 15 [2] 15 04 [2] 5b 08 [2] 57 02 [2] 40 09 [2] 5b 47 [2] 66 }

  condition:
    any of them
}