rule TTP_XOR_MULT_DOSStub_bc7f {
  strings:
    $key_bc7f = { e8 17 [2] 9c 0f [2] db 0d [2] 9c 1c [2] d2 10 [2] de 1a [2] c9 11 [2] d2 5f [2] ef }

  condition:
    any of them
}