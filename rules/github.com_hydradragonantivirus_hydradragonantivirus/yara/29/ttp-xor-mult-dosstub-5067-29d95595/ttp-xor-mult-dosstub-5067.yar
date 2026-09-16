rule TTP_XOR_MULT_DOSStub_5067 {
  strings:
    $key_5067 = { 04 0f [2] 70 17 [2] 37 15 [2] 70 04 [2] 3e 08 [2] 32 02 [2] 25 09 [2] 3e 47 [2] 03 }

  condition:
    any of them
}