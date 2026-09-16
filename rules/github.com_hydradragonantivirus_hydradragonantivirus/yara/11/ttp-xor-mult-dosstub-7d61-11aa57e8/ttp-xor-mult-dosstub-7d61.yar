rule TTP_XOR_MULT_DOSStub_7d61 {
  strings:
    $key_7d61 = { 29 09 [2] 5d 11 [2] 1a 13 [2] 5d 02 [2] 13 0e [2] 1f 04 [2] 08 0f [2] 13 41 [2] 2e }

  condition:
    any of them
}