rule TTP_XOR_MULT_DOSStub_1b0b {
  strings:
    $key_1b0b = { 4f 63 [2] 3b 7b [2] 7c 79 [2] 3b 68 [2] 75 64 [2] 79 6e [2] 6e 65 [2] 75 2b [2] 48 }

  condition:
    any of them
}