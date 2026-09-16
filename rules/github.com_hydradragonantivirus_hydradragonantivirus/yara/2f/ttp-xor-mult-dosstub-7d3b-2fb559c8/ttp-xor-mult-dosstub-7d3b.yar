rule TTP_XOR_MULT_DOSStub_7d3b {
  strings:
    $key_7d3b = { 29 53 [2] 5d 4b [2] 1a 49 [2] 5d 58 [2] 13 54 [2] 1f 5e [2] 08 55 [2] 13 1b [2] 2e }

  condition:
    any of them
}