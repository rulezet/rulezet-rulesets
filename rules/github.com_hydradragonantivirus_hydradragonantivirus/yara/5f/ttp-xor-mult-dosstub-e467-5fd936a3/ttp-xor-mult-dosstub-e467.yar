rule TTP_XOR_MULT_DOSStub_e467 {
  strings:
    $key_e467 = { b0 0f [2] c4 17 [2] 83 15 [2] c4 04 [2] 8a 08 [2] 86 02 [2] 91 09 [2] 8a 47 [2] b7 }

  condition:
    any of them
}