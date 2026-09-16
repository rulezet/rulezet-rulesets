rule TTP_XOR_MULT_DOSStub_6a7b {
  strings:
    $key_6a7b = { 3e 13 [2] 4a 0b [2] 0d 09 [2] 4a 18 [2] 04 14 [2] 08 1e [2] 1f 15 [2] 04 5b [2] 39 }

  condition:
    any of them
}