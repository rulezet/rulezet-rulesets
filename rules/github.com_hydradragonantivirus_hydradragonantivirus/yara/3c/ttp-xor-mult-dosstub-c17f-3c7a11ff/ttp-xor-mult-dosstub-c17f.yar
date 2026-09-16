rule TTP_XOR_MULT_DOSStub_c17f {
  strings:
    $key_c17f = { 95 17 [2] e1 0f [2] a6 0d [2] e1 1c [2] af 10 [2] a3 1a [2] b4 11 [2] af 5f [2] 92 }

  condition:
    any of them
}