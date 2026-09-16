rule TTP_XOR_MULT_DOSStub_287b {
  strings:
    $key_287b = { 7c 13 [2] 08 0b [2] 4f 09 [2] 08 18 [2] 46 14 [2] 4a 1e [2] 5d 15 [2] 46 5b [2] 7b }

  condition:
    any of them
}