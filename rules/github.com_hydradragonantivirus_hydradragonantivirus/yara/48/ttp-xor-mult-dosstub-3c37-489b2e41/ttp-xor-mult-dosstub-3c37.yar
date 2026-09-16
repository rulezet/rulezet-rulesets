rule TTP_XOR_MULT_DOSStub_3c37 {
  strings:
    $key_3c37 = { 68 5f [2] 1c 47 [2] 5b 45 [2] 1c 54 [2] 52 58 [2] 5e 52 [2] 49 59 [2] 52 17 [2] 6f }

  condition:
    any of them
}