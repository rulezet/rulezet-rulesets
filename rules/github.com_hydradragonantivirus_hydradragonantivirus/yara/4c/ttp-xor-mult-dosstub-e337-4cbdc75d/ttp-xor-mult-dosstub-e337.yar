rule TTP_XOR_MULT_DOSStub_e337 {
  strings:
    $key_e337 = { b7 5f [2] c3 47 [2] 84 45 [2] c3 54 [2] 8d 58 [2] 81 52 [2] 96 59 [2] 8d 17 [2] b0 }

  condition:
    any of them
}