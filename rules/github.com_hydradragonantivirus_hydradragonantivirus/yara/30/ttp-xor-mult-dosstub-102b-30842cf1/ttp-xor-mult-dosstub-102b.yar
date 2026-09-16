rule TTP_XOR_MULT_DOSStub_102b {
  strings:
    $key_102b = { 44 43 [2] 30 5b [2] 77 59 [2] 30 48 [2] 7e 44 [2] 72 4e [2] 65 45 [2] 7e 0b [2] 43 }

  condition:
    any of them
}