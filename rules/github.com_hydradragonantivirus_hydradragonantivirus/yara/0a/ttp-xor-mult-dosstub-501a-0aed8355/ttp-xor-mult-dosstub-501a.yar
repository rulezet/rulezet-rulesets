rule TTP_XOR_MULT_DOSStub_501a {
  strings:
    $key_501a = { 04 72 [2] 70 6a [2] 37 68 [2] 70 79 [2] 3e 75 [2] 32 7f [2] 25 74 [2] 3e 3a [2] 03 }

  condition:
    any of them
}