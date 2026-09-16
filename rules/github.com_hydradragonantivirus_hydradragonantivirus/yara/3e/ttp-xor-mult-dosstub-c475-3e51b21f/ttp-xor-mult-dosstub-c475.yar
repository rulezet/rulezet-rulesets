rule TTP_XOR_MULT_DOSStub_c475 {
  strings:
    $key_c475 = { 90 1d [2] e4 05 [2] a3 07 [2] e4 16 [2] aa 1a [2] a6 10 [2] b1 1b [2] aa 55 [2] 97 }

  condition:
    any of them
}