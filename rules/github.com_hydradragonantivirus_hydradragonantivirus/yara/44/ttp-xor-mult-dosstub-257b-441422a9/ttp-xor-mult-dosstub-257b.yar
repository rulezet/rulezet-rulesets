rule TTP_XOR_MULT_DOSStub_257b {
  strings:
    $key_257b = { 71 13 [2] 05 0b [2] 42 09 [2] 05 18 [2] 4b 14 [2] 47 1e [2] 50 15 [2] 4b 5b [2] 76 }

  condition:
    any of them
}