rule TTP_XOR_MULT_DOSStub_5b1b {
  strings:
    $key_5b1b = { 0f 73 [2] 7b 6b [2] 3c 69 [2] 7b 78 [2] 35 74 [2] 39 7e [2] 2e 75 [2] 35 3b [2] 08 }

  condition:
    any of them
}