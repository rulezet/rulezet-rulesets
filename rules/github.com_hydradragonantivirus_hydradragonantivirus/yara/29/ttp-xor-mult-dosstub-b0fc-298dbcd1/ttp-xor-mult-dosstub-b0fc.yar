rule TTP_XOR_MULT_DOSStub_b0fc {
  strings:
    $key_b0fc = { e4 94 [2] 90 8c [2] d7 8e [2] 90 9f [2] de 93 [2] d2 99 [2] c5 92 [2] de dc [2] e3 }

  condition:
    any of them
}