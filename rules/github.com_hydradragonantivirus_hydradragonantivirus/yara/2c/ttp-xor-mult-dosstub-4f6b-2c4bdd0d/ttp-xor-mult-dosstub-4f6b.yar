rule TTP_XOR_MULT_DOSStub_4f6b {
  strings:
    $key_4f6b = { 1b 03 [2] 6f 1b [2] 28 19 [2] 6f 08 [2] 21 04 [2] 2d 0e [2] 3a 05 [2] 21 4b [2] 1c }

  condition:
    any of them
}