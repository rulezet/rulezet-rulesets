rule TTP_XOR_MULT_DOSStub_0067 {
  strings:
    $key_0067 = { 54 0f [2] 20 17 [2] 67 15 [2] 20 04 [2] 6e 08 [2] 62 02 [2] 75 09 [2] 6e 47 [2] 53 }

  condition:
    any of them
}