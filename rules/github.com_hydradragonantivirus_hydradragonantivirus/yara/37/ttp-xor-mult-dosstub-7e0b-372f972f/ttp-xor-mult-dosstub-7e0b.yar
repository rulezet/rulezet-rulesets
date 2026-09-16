rule TTP_XOR_MULT_DOSStub_7e0b {
  strings:
    $key_7e0b = { 2a 63 [2] 5e 7b [2] 19 79 [2] 5e 68 [2] 10 64 [2] 1c 6e [2] 0b 65 [2] 10 2b [2] 2d }

  condition:
    any of them
}