rule TTP_XOR_MULT_DOSStub_e268 {
  strings:
    $key_e268 = { b6 00 [2] c2 18 [2] 85 1a [2] c2 0b [2] 8c 07 [2] 80 0d [2] 97 06 [2] 8c 48 [2] b1 }

  condition:
    any of them
}