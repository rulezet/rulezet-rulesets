rule TTP_XOR_MULT_DOSStub_bc2f {
  strings:
    $key_bc2f = { e8 47 [2] 9c 5f [2] db 5d [2] 9c 4c [2] d2 40 [2] de 4a [2] c9 41 [2] d2 0f [2] ef }

  condition:
    any of them
}