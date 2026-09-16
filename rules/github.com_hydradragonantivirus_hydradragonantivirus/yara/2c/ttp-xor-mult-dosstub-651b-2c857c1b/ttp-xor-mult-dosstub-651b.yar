rule TTP_XOR_MULT_DOSStub_651b {
  strings:
    $key_651b = { 31 73 [2] 45 6b [2] 02 69 [2] 45 78 [2] 0b 74 [2] 07 7e [2] 10 75 [2] 0b 3b [2] 36 }

  condition:
    any of them
}