rule TTP_XOR_MULT_DOSStub_281b {
  strings:
    $key_281b = { 7c 73 [2] 08 6b [2] 4f 69 [2] 08 78 [2] 46 74 [2] 4a 7e [2] 5d 75 [2] 46 3b [2] 7b }

  condition:
    any of them
}