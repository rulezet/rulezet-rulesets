rule TTP_XOR_MULT_DOSStub_b748 {
  strings:
    $key_b748 = { e3 20 [2] 97 38 [2] d0 3a [2] 97 2b [2] d9 27 [2] d5 2d [2] c2 26 [2] d9 68 [2] e4 }

  condition:
    any of them
}