rule TTP_XOR_MULT_DOSStub_3c1b {
  strings:
    $key_3c1b = { 68 73 [2] 1c 6b [2] 5b 69 [2] 1c 78 [2] 52 74 [2] 5e 7e [2] 49 75 [2] 52 3b [2] 6f }

  condition:
    any of them
}