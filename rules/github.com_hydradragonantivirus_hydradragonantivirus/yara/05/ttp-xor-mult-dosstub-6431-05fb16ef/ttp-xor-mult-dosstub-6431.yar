rule TTP_XOR_MULT_DOSStub_6431 {
  strings:
    $key_6431 = { 30 59 [2] 44 41 [2] 03 43 [2] 44 52 [2] 0a 5e [2] 06 54 [2] 11 5f [2] 0a 11 [2] 37 }

  condition:
    any of them
}