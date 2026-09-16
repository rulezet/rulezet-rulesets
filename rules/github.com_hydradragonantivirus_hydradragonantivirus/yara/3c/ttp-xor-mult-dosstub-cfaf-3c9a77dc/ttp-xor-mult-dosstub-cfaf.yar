rule TTP_XOR_MULT_DOSStub_cfaf {
  strings:
    $key_cfaf = { 9b c7 [2] ef df [2] a8 dd [2] ef cc [2] a1 c0 [2] ad ca [2] ba c1 [2] a1 8f [2] 9c }

  condition:
    any of them
}