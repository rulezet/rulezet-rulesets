rule TTP_XOR_MULT_DOSStub_6f6b {
  strings:
    $key_6f6b = { 3b 03 [2] 4f 1b [2] 08 19 [2] 4f 08 [2] 01 04 [2] 0d 0e [2] 1a 05 [2] 01 4b [2] 3c }

  condition:
    any of them
}