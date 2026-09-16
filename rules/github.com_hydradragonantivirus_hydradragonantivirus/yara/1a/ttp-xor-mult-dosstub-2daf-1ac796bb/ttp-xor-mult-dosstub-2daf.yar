rule TTP_XOR_MULT_DOSStub_2daf {
  strings:
    $key_2daf = { 79 c7 [2] 0d df [2] 4a dd [2] 0d cc [2] 43 c0 [2] 4f ca [2] 58 c1 [2] 43 8f [2] 7e }

  condition:
    any of them
}