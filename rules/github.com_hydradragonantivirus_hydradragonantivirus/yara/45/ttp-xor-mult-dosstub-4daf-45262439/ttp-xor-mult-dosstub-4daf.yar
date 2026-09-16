rule TTP_XOR_MULT_DOSStub_4daf {
  strings:
    $key_4daf = { 19 c7 [2] 6d df [2] 2a dd [2] 6d cc [2] 23 c0 [2] 2f ca [2] 38 c1 [2] 23 8f [2] 1e }

  condition:
    any of them
}