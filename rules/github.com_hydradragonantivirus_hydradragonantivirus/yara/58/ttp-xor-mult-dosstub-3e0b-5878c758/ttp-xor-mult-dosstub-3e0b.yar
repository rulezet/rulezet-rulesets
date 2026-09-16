rule TTP_XOR_MULT_DOSStub_3e0b {
  strings:
    $key_3e0b = { 6a 63 [2] 1e 7b [2] 59 79 [2] 1e 68 [2] 50 64 [2] 5c 6e [2] 4b 65 [2] 50 2b [2] 6d }

  condition:
    any of them
}