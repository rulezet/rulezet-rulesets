rule TTP_XOR_MULT_DOSStub_e310 {
  strings:
    $key_e310 = { b7 78 [2] c3 60 [2] 84 62 [2] c3 73 [2] 8d 7f [2] 81 75 [2] 96 7e [2] 8d 30 [2] b0 }

  condition:
    any of them
}