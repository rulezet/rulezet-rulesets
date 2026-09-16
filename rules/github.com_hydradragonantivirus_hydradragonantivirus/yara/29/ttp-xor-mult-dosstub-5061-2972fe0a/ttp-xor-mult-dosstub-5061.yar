rule TTP_XOR_MULT_DOSStub_5061 {
  strings:
    $key_5061 = { 04 09 [2] 70 11 [2] 37 13 [2] 70 02 [2] 3e 0e [2] 32 04 [2] 25 0f [2] 3e 41 [2] 03 }

  condition:
    any of them
}