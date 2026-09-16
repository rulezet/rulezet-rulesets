rule TTP_XOR_MULT_DOSStub_c46f {
  strings:
    $key_c46f = { 90 07 [2] e4 1f [2] a3 1d [2] e4 0c [2] aa 00 [2] a6 0a [2] b1 01 [2] aa 4f [2] 97 }

  condition:
    any of them
}