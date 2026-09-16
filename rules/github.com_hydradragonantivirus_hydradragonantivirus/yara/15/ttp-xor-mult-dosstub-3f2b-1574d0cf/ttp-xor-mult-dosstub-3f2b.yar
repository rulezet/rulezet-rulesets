rule TTP_XOR_MULT_DOSStub_3f2b {
  strings:
    $key_3f2b = { 6b 43 [2] 1f 5b [2] 58 59 [2] 1f 48 [2] 51 44 [2] 5d 4e [2] 4a 45 [2] 51 0b [2] 6c }

  condition:
    any of them
}