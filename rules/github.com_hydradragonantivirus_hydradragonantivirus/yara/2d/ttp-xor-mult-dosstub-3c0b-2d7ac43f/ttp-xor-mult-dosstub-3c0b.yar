rule TTP_XOR_MULT_DOSStub_3c0b {
  strings:
    $key_3c0b = { 68 63 [2] 1c 7b [2] 5b 79 [2] 1c 68 [2] 52 64 [2] 5e 6e [2] 49 65 [2] 52 2b [2] 6f }

  condition:
    any of them
}