rule TTP_XOR_MULT_DOSStub_283b {
  strings:
    $key_283b = { 7c 53 [2] 08 4b [2] 4f 49 [2] 08 58 [2] 46 54 [2] 4a 5e [2] 5d 55 [2] 46 1b [2] 7b }

  condition:
    any of them
}