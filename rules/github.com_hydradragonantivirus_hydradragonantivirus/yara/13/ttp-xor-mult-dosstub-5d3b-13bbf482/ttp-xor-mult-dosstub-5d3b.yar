rule TTP_XOR_MULT_DOSStub_5d3b {
  strings:
    $key_5d3b = { 09 53 [2] 7d 4b [2] 3a 49 [2] 7d 58 [2] 33 54 [2] 3f 5e [2] 28 55 [2] 33 1b [2] 0e }

  condition:
    any of them
}