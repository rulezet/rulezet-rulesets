rule TTP_XOR_MULT_DOSStub_3f6b {
  strings:
    $key_3f6b = { 6b 03 [2] 1f 1b [2] 58 19 [2] 1f 08 [2] 51 04 [2] 5d 0e [2] 4a 05 [2] 51 4b [2] 6c }

  condition:
    any of them
}