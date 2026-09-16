rule TTP_XOR_MULT_DOSStub_bcfd {
  strings:
    $key_bcfd = { e8 95 [2] 9c 8d [2] db 8f [2] 9c 9e [2] d2 92 [2] de 98 [2] c9 93 [2] d2 dd [2] ef }

  condition:
    any of them
}