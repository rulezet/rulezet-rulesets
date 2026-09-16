rule TTP_XOR_MULT_DOSStub_bcef {
  strings:
    $key_bcef = { e8 87 [2] 9c 9f [2] db 9d [2] 9c 8c [2] d2 80 [2] de 8a [2] c9 81 [2] d2 cf [2] ef }

  condition:
    any of them
}