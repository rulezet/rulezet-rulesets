rule TTP_XOR_MULT_DOSStub_121a {
  strings:
    $key_121a = { 46 72 [2] 32 6a [2] 75 68 [2] 32 79 [2] 7c 75 [2] 70 7f [2] 67 74 [2] 7c 3a [2] 41 }

  condition:
    any of them
}