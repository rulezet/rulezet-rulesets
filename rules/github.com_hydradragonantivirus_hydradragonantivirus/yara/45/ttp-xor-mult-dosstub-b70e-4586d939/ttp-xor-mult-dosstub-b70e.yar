rule TTP_XOR_MULT_DOSStub_b70e {
  strings:
    $key_b70e = { e3 66 [2] 97 7e [2] d0 7c [2] 97 6d [2] d9 61 [2] d5 6b [2] c2 60 [2] d9 2e [2] e4 }

  condition:
    any of them
}