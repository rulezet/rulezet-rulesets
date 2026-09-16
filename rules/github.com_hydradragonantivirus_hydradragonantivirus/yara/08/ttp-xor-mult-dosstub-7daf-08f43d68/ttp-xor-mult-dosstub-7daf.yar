rule TTP_XOR_MULT_DOSStub_7daf {
  strings:
    $key_7daf = { 29 c7 [2] 5d df [2] 1a dd [2] 5d cc [2] 13 c0 [2] 1f ca [2] 08 c1 [2] 13 8f [2] 2e }

  condition:
    any of them
}