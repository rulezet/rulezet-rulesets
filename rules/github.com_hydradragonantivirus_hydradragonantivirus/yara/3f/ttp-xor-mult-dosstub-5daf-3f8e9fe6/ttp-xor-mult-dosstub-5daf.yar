rule TTP_XOR_MULT_DOSStub_5daf {
  strings:
    $key_5daf = { 09 c7 [2] 7d df [2] 3a dd [2] 7d cc [2] 33 c0 [2] 3f ca [2] 28 c1 [2] 33 8f [2] 0e }

  condition:
    any of them
}