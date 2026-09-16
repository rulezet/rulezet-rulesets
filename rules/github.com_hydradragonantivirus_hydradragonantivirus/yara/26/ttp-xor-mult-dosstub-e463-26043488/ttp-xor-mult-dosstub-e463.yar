rule TTP_XOR_MULT_DOSStub_e463 {
  strings:
    $key_e463 = { b0 0b [2] c4 13 [2] 83 11 [2] c4 00 [2] 8a 0c [2] 86 06 [2] 91 0d [2] 8a 43 [2] b7 }

  condition:
    any of them
}