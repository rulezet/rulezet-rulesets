rule TTP_XOR_MULT_DOSStub_5567 {
  strings:
    $key_5567 = { 01 0f [2] 75 17 [2] 32 15 [2] 75 04 [2] 3b 08 [2] 37 02 [2] 20 09 [2] 3b 47 [2] 06 }

  condition:
    any of them
}