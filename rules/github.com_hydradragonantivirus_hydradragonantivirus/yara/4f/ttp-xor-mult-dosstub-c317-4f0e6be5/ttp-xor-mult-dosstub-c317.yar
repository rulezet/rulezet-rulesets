rule TTP_XOR_MULT_DOSStub_c317 {
  strings:
    $key_c317 = { 97 7f [2] e3 67 [2] a4 65 [2] e3 74 [2] ad 78 [2] a1 72 [2] b6 79 [2] ad 37 [2] 90 }

  condition:
    any of them
}