rule TTP_XOR_MULT_DOSStub_4eae {
  strings:
    $key_4eae = { 1a c6 [2] 6e de [2] 29 dc [2] 6e cd [2] 20 c1 [2] 2c cb [2] 3b c0 [2] 20 8e [2] 1d }

  condition:
    any of them
}