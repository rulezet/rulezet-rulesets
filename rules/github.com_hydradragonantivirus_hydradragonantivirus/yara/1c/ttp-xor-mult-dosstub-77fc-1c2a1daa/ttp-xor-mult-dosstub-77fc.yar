rule TTP_XOR_MULT_DOSStub_77fc {
  strings:
    $key_77fc = { 23 94 [2] 57 8c [2] 10 8e [2] 57 9f [2] 19 93 [2] 15 99 [2] 02 92 [2] 19 dc [2] 24 }

  condition:
    any of them
}