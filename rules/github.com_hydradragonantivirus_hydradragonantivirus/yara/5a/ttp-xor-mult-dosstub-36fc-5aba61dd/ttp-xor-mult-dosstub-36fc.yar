rule TTP_XOR_MULT_DOSStub_36fc {
  strings:
    $key_36fc = { 62 94 [2] 16 8c [2] 51 8e [2] 16 9f [2] 58 93 [2] 54 99 [2] 43 92 [2] 58 dc [2] 65 }

  condition:
    any of them
}