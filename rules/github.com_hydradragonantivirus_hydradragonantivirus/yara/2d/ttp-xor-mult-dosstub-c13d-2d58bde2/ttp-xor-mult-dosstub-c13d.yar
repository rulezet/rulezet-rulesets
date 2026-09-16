rule TTP_XOR_MULT_DOSStub_c13d {
  strings:
    $key_c13d = { 95 55 [2] e1 4d [2] a6 4f [2] e1 5e [2] af 52 [2] a3 58 [2] b4 53 [2] af 1d [2] 92 }

  condition:
    any of them
}