rule TTP_XOR_MULT_DOSStub_e479 {
  strings:
    $key_e479 = { b0 11 [2] c4 09 [2] 83 0b [2] c4 1a [2] 8a 16 [2] 86 1c [2] 91 17 [2] 8a 59 [2] b7 }

  condition:
    any of them
}