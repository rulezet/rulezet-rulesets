rule TTP_XOR_MULT_DOSStub_3936 {
  strings:
    $key_3936 = { 6d 5e [2] 19 46 [2] 5e 44 [2] 19 55 [2] 57 59 [2] 5b 53 [2] 4c 58 [2] 57 16 [2] 6a }

  condition:
    any of them
}