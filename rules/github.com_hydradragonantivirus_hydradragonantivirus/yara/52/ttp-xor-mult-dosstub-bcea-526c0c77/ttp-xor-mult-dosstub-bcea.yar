rule TTP_XOR_MULT_DOSStub_bcea {
  strings:
    $key_bcea = { e8 82 [2] 9c 9a [2] db 98 [2] 9c 89 [2] d2 85 [2] de 8f [2] c9 84 [2] d2 ca [2] ef }

  condition:
    any of them
}