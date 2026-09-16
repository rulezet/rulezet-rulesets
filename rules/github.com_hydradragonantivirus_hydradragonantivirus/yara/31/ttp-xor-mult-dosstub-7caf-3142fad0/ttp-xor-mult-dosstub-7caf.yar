rule TTP_XOR_MULT_DOSStub_7caf {
  strings:
    $key_7caf = { 28 c7 [2] 5c df [2] 1b dd [2] 5c cc [2] 12 c0 [2] 1e ca [2] 09 c1 [2] 12 8f [2] 2f }

  condition:
    any of them
}