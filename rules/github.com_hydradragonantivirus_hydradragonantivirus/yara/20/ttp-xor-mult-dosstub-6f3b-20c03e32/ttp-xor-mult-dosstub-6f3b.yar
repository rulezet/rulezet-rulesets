rule TTP_XOR_MULT_DOSStub_6f3b {
  strings:
    $key_6f3b = { 3b 53 [2] 4f 4b [2] 08 49 [2] 4f 58 [2] 01 54 [2] 0d 5e [2] 1a 55 [2] 01 1b [2] 3c }

  condition:
    any of them
}