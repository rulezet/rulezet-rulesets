rule TTP_XOR_MULT_DOSStub_b70f {
  strings:
    $key_b70f = { e3 67 [2] 97 7f [2] d0 7d [2] 97 6c [2] d9 60 [2] d5 6a [2] c2 61 [2] d9 2f [2] e4 }

  condition:
    any of them
}