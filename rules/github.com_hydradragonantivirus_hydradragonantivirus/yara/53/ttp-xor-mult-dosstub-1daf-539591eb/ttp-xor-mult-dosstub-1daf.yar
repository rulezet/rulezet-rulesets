rule TTP_XOR_MULT_DOSStub_1daf {
  strings:
    $key_1daf = { 49 c7 [2] 3d df [2] 7a dd [2] 3d cc [2] 73 c0 [2] 7f ca [2] 68 c1 [2] 73 8f [2] 4e }

  condition:
    any of them
}