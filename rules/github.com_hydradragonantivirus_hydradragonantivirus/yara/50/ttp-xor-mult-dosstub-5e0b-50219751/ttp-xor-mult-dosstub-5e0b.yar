rule TTP_XOR_MULT_DOSStub_5e0b {
  strings:
    $key_5e0b = { 0a 63 [2] 7e 7b [2] 39 79 [2] 7e 68 [2] 30 64 [2] 3c 6e [2] 2b 65 [2] 30 2b [2] 0d }

  condition:
    any of them
}