rule TTP_XOR_MULT_DOSStub_123a {
  strings:
    $key_123a = { 46 52 [2] 32 4a [2] 75 48 [2] 32 59 [2] 7c 55 [2] 70 5f [2] 67 54 [2] 7c 1a [2] 41 }

  condition:
    any of them
}