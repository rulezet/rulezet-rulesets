rule TTP_XOR_MULT_DOSStub_b7fc {
  strings:
    $key_b7fc = { e3 94 [2] 97 8c [2] d0 8e [2] 97 9f [2] d9 93 [2] d5 99 [2] c2 92 [2] d9 dc [2] e4 }

  condition:
    any of them
}