rule TTP_XOR_MULT_DOSStub_b65e {
  strings:
    $key_b65e = { e2 36 [2] 96 2e [2] d1 2c [2] 96 3d [2] d8 31 [2] d4 3b [2] c3 30 [2] d8 7e [2] e5 }

  condition:
    any of them
}