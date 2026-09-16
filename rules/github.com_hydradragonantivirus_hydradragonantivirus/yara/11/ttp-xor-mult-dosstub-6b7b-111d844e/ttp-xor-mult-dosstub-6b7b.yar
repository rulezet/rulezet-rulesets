rule TTP_XOR_MULT_DOSStub_6b7b {
  strings:
    $key_6b7b = { 3f 13 [2] 4b 0b [2] 0c 09 [2] 4b 18 [2] 05 14 [2] 09 1e [2] 1e 15 [2] 05 5b [2] 38 }

  condition:
    any of them
}