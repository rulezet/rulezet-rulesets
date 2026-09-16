rule TTP_XOR_MULT_DOSStub_122a {
  strings:
    $key_122a = { 46 42 [2] 32 5a [2] 75 58 [2] 32 49 [2] 7c 45 [2] 70 4f [2] 67 44 [2] 7c 0a [2] 41 }

  condition:
    any of them
}