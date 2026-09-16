rule TTP_XOR_MULT_DOSStub_c13b {
  strings:
    $key_c13b = { 95 53 [2] e1 4b [2] a6 49 [2] e1 58 [2] af 54 [2] a3 5e [2] b4 55 [2] af 1b [2] 92 }

  condition:
    any of them
}