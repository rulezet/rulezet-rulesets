rule TTP_XOR_MULT_DOSStub_bc6c {
  strings:
    $key_bc6c = { e8 04 [2] 9c 1c [2] db 1e [2] 9c 0f [2] d2 03 [2] de 09 [2] c9 02 [2] d2 4c [2] ef }

  condition:
    any of them
}