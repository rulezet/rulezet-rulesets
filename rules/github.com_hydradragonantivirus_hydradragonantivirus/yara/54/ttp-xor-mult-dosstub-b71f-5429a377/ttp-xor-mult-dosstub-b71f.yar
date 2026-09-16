rule TTP_XOR_MULT_DOSStub_b71f {
  strings:
    $key_b71f = { e3 77 [2] 97 6f [2] d0 6d [2] 97 7c [2] d9 70 [2] d5 7a [2] c2 71 [2] d9 3f [2] e4 }

  condition:
    any of them
}