rule TTP_XOR_MULT_DOSStub_4faf {
  strings:
    $key_4faf = { 1b c7 [2] 6f df [2] 28 dd [2] 6f cc [2] 21 c0 [2] 2d ca [2] 3a c1 [2] 21 8f [2] 1c }

  condition:
    any of them
}