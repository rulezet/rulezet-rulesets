rule TTP_XOR_MULT_DOSStub_e461 {
  strings:
    $key_e461 = { b0 09 [2] c4 11 [2] 83 13 [2] c4 02 [2] 8a 0e [2] 86 04 [2] 91 0f [2] 8a 41 [2] b7 }

  condition:
    any of them
}