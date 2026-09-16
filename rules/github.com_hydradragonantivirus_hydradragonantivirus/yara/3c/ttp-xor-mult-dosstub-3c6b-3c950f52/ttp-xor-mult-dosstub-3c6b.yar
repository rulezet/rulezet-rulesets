rule TTP_XOR_MULT_DOSStub_3c6b {
  strings:
    $key_3c6b = { 68 03 [2] 1c 1b [2] 5b 19 [2] 1c 08 [2] 52 04 [2] 5e 0e [2] 49 05 [2] 52 4b [2] 6f }

  condition:
    any of them
}