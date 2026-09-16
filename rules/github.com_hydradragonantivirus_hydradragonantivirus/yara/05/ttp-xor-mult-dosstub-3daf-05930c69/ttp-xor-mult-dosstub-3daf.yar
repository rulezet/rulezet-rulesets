rule TTP_XOR_MULT_DOSStub_3daf {
  strings:
    $key_3daf = { 69 c7 [2] 1d df [2] 5a dd [2] 1d cc [2] 53 c0 [2] 5f ca [2] 48 c1 [2] 53 8f [2] 6e }

  condition:
    any of them
}