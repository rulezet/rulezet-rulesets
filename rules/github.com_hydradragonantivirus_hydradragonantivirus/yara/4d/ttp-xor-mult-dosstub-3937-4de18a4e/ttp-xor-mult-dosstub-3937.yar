rule TTP_XOR_MULT_DOSStub_3937 {
  strings:
    $key_3937 = { 6d 5f [2] 19 47 [2] 5e 45 [2] 19 54 [2] 57 58 [2] 5b 52 [2] 4c 59 [2] 57 17 [2] 6a }

  condition:
    any of them
}