rule TTP_XOR_MULT_DOSStub_2f6b {
  strings:
    $key_2f6b = { 7b 03 [2] 0f 1b [2] 48 19 [2] 0f 08 [2] 41 04 [2] 4d 0e [2] 5a 05 [2] 41 4b [2] 7c }

  condition:
    any of them
}