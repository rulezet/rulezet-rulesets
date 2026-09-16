rule TTP_XOR_MULT_DOSStub_0f2b {
  strings:
    $key_0f2b = { 5b 43 [2] 2f 5b [2] 68 59 [2] 2f 48 [2] 61 44 [2] 6d 4e [2] 7a 45 [2] 61 0b [2] 5c }

  condition:
    any of them
}