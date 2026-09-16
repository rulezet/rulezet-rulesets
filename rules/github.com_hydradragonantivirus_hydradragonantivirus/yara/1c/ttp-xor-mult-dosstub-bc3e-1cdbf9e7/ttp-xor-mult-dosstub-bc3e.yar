rule TTP_XOR_MULT_DOSStub_bc3e {
  strings:
    $key_bc3e = { e8 56 [2] 9c 4e [2] db 4c [2] 9c 5d [2] d2 51 [2] de 5b [2] c9 50 [2] d2 1e [2] ef }

  condition:
    any of them
}