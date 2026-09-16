rule TTP_XOR_MULT_DOSStub_25fc {
  strings:
    $key_25fc = { 71 94 [2] 05 8c [2] 42 8e [2] 05 9f [2] 4b 93 [2] 47 99 [2] 50 92 [2] 4b dc [2] 76 }

  condition:
    any of them
}