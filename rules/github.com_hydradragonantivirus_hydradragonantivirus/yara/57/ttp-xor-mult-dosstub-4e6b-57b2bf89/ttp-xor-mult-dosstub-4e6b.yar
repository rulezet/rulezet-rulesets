rule TTP_XOR_MULT_DOSStub_4e6b {
  strings:
    $key_4e6b = { 1a 03 [2] 6e 1b [2] 29 19 [2] 6e 08 [2] 20 04 [2] 2c 0e [2] 3b 05 [2] 20 4b [2] 1d }

  condition:
    any of them
}