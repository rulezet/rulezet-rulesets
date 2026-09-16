rule TTP_XOR_MULT_DOSStub_2f7b {
  strings:
    $key_2f7b = { 7b 13 [2] 0f 0b [2] 48 09 [2] 0f 18 [2] 41 14 [2] 4d 1e [2] 5a 15 [2] 41 5b [2] 7c }

  condition:
    any of them
}