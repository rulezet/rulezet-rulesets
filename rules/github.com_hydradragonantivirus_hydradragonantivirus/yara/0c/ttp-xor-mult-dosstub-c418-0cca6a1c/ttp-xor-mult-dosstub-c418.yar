rule TTP_XOR_MULT_DOSStub_c418 {
  strings:
    $key_c418 = { 90 70 [2] e4 68 [2] a3 6a [2] e4 7b [2] aa 77 [2] a6 7d [2] b1 76 [2] aa 38 [2] 97 }

  condition:
    any of them
}