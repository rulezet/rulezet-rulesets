rule TTP_XOR_MULT_DOSStub_c17e {
  strings:
    $key_c17e = { 95 16 [2] e1 0e [2] a6 0c [2] e1 1d [2] af 11 [2] a3 1b [2] b4 10 [2] af 5e [2] 92 }

  condition:
    any of them
}