rule TTP_XOR_MULT_DOSStub_c3fc {
  strings:
    $key_c3fc = { 97 94 [2] e3 8c [2] a4 8e [2] e3 9f [2] ad 93 [2] a1 99 [2] b6 92 [2] ad dc [2] 90 }

  condition:
    any of them
}