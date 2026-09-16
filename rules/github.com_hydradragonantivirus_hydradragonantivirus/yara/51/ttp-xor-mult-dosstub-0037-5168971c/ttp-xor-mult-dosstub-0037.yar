rule TTP_XOR_MULT_DOSStub_0037 {
  strings:
    $key_0037 = { 54 5f [2] 20 47 [2] 67 45 [2] 20 54 [2] 6e 58 [2] 62 52 [2] 75 59 [2] 6e 17 [2] 53 }

  condition:
    any of them
}