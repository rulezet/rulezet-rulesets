rule TTP_XOR_MULT_DOSStub_7937 {
  strings:
    $key_7937 = { 2d 5f [2] 59 47 [2] 1e 45 [2] 59 54 [2] 17 58 [2] 1b 52 [2] 0c 59 [2] 17 17 [2] 2a }

  condition:
    any of them
}