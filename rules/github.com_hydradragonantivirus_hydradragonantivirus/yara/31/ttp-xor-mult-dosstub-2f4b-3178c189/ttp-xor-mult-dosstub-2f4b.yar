rule TTP_XOR_MULT_DOSStub_2f4b {
  strings:
    $key_2f4b = { 7b 23 [2] 0f 3b [2] 48 39 [2] 0f 28 [2] 41 24 [2] 4d 2e [2] 5a 25 [2] 41 6b [2] 7c }

  condition:
    any of them
}