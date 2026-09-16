rule TTP_XOR_MULT_DOSStub_1e1b {
  strings:
    $key_1e1b = { 4a 73 [2] 3e 6b [2] 79 69 [2] 3e 78 [2] 70 74 [2] 7c 7e [2] 6b 75 [2] 70 3b [2] 4d }

  condition:
    any of them
}