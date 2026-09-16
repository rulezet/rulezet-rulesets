rule TTP_XOR_MULT_DOSStub_c12c {
  strings:
    $key_c12c = { 95 44 [2] e1 5c [2] a6 5e [2] e1 4f [2] af 43 [2] a3 49 [2] b4 42 [2] af 0c [2] 92 }

  condition:
    any of them
}