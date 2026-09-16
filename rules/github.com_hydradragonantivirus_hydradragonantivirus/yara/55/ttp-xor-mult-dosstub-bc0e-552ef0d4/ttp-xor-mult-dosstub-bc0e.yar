rule TTP_XOR_MULT_DOSStub_bc0e {
  strings:
    $key_bc0e = { e8 66 [2] 9c 7e [2] db 7c [2] 9c 6d [2] d2 61 [2] de 6b [2] c9 60 [2] d2 2e [2] ef }

  condition:
    any of them
}