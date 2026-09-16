rule TTP_XOR_MULT_DOSStub_e378 {
  strings:
    $key_e378 = { b7 10 [2] c3 08 [2] 84 0a [2] c3 1b [2] 8d 17 [2] 81 1d [2] 96 16 [2] 8d 58 [2] b0 }

  condition:
    any of them
}