rule TTP_XOR_MULT_DOSStub_bcec {
  strings:
    $key_bcec = { e8 84 [2] 9c 9c [2] db 9e [2] 9c 8f [2] d2 83 [2] de 89 [2] c9 82 [2] d2 cc [2] ef }

  condition:
    any of them
}