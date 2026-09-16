rule TTP_XOR_MULT_DOSStub_0567 {
  strings:
    $key_0567 = { 51 0f [2] 25 17 [2] 62 15 [2] 25 04 [2] 6b 08 [2] 67 02 [2] 70 09 [2] 6b 47 [2] 56 }

  condition:
    any of them
}