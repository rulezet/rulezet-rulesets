rule TTP_XOR_MULT_DOSStub_0e0b {
  strings:
    $key_0e0b = { 5a 63 [2] 2e 7b [2] 69 79 [2] 2e 68 [2] 60 64 [2] 6c 6e [2] 7b 65 [2] 60 2b [2] 5d }

  condition:
    any of them
}