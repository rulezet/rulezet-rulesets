rule TTP_XOR_MULT_DOSStub_bc03 {
  strings:
    $key_bc03 = { e8 6b [2] 9c 73 [2] db 71 [2] 9c 60 [2] d2 6c [2] de 66 [2] c9 6d [2] d2 23 [2] ef }

  condition:
    any of them
}