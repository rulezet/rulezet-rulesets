rule TTP_XOR_MULT_DOSStub_c16a {
  strings:
    $key_c16a = { 95 02 [2] e1 1a [2] a6 18 [2] e1 09 [2] af 05 [2] a3 0f [2] b4 04 [2] af 4a [2] 92 }

  condition:
    any of them
}