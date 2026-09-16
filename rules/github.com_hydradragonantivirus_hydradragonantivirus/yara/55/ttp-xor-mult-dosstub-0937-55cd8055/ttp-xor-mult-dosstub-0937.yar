rule TTP_XOR_MULT_DOSStub_0937 {
  strings:
    $key_0937 = { 5d 5f [2] 29 47 [2] 6e 45 [2] 29 54 [2] 67 58 [2] 6b 52 [2] 7c 59 [2] 67 17 [2] 5a }

  condition:
    any of them
}