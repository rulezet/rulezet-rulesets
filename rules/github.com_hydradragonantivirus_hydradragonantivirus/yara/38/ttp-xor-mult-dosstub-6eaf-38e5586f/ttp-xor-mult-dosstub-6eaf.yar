rule TTP_XOR_MULT_DOSStub_6eaf {
  strings:
    $key_6eaf = { 3a c7 [2] 4e df [2] 09 dd [2] 4e cc [2] 00 c0 [2] 0c ca [2] 1b c1 [2] 00 8f [2] 3d }

  condition:
    any of them
}