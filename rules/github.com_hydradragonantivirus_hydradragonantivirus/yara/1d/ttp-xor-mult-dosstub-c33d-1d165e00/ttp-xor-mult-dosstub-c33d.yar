rule TTP_XOR_MULT_DOSStub_c33d {
  strings:
    $key_c33d = { 97 55 [2] e3 4d [2] a4 4f [2] e3 5e [2] ad 52 [2] a1 58 [2] b6 53 [2] ad 1d [2] 90 }

  condition:
    any of them
}