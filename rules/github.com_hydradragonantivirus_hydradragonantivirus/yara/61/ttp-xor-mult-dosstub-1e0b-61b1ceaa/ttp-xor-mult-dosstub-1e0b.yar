rule TTP_XOR_MULT_DOSStub_1e0b {
  strings:
    $key_1e0b = { 4a 63 [2] 3e 7b [2] 79 79 [2] 3e 68 [2] 70 64 [2] 7c 6e [2] 6b 65 [2] 70 2b [2] 4d }

  condition:
    any of them
}