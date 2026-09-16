rule TTP_XOR_MULT_DOSStub_3830 {
  strings:
    $key_3830 = { 6c 58 [2] 18 40 [2] 5f 42 [2] 18 53 [2] 56 5f [2] 5a 55 [2] 4d 5e [2] 56 10 [2] 6b }

  condition:
    any of them
}