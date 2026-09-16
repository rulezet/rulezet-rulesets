rule TTP_XOR_MULT_DOSStub_6c6b {
  strings:
    $key_6c6b = { 38 03 [2] 4c 1b [2] 0b 19 [2] 4c 08 [2] 02 04 [2] 0e 0e [2] 19 05 [2] 02 4b [2] 3f }

  condition:
    any of them
}