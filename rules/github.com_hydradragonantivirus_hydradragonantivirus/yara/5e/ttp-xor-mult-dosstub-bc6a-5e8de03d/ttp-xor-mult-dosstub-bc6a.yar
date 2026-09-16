rule TTP_XOR_MULT_DOSStub_bc6a {
  strings:
    $key_bc6a = { e8 02 [2] 9c 1a [2] db 18 [2] 9c 09 [2] d2 05 [2] de 0f [2] c9 04 [2] d2 4a [2] ef }

  condition:
    any of them
}