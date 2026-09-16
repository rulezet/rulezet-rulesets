rule TTP_XOR_MULT_DOSStub_7837 {
  strings:
    $key_7837 = { 2c 5f [2] 58 47 [2] 1f 45 [2] 58 54 [2] 16 58 [2] 1a 52 [2] 0d 59 [2] 16 17 [2] 2b }

  condition:
    any of them
}