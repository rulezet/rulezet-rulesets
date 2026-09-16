rule TTP_XOR_MULT_DOSStub_cfba {
  strings:
    $key_cfba = { 9b d2 [2] ef ca [2] a8 c8 [2] ef d9 [2] a1 d5 [2] ad df [2] ba d4 [2] a1 9a [2] 9c }

  condition:
    any of them
}