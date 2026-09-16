rule TTP_XOR_MULT_DOSStub_5faf {
  strings:
    $key_5faf = { 0b c7 [2] 7f df [2] 38 dd [2] 7f cc [2] 31 c0 [2] 3d ca [2] 2a c1 [2] 31 8f [2] 0c }

  condition:
    any of them
}