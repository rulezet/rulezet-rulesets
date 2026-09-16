rule TTP_XOR_MULT_DOSStub_c10c {
  strings:
    $key_c10c = { 95 64 [2] e1 7c [2] a6 7e [2] e1 6f [2] af 63 [2] a3 69 [2] b4 62 [2] af 2c [2] 92 }

  condition:
    any of them
}