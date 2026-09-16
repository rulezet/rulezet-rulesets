rule TTP_XOR_MULT_DOSStub_c1fc {
  strings:
    $key_c1fc = { 95 94 [2] e1 8c [2] a6 8e [2] e1 9f [2] af 93 [2] a3 99 [2] b4 92 [2] af dc [2] 92 }

  condition:
    any of them
}