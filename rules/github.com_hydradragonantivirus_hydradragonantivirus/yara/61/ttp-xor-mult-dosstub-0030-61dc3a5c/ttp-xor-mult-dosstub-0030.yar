rule TTP_XOR_MULT_DOSStub_0030 {
  strings:
    $key_0030 = { 54 58 [2] 20 40 [2] 67 42 [2] 20 53 [2] 6e 5f [2] 62 55 [2] 75 5e [2] 6e 10 [2] 53 }

  condition:
    any of them
}