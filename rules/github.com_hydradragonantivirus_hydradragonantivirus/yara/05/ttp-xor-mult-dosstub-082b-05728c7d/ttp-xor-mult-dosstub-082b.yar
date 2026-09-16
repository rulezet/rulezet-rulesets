rule TTP_XOR_MULT_DOSStub_082b {
  strings:
    $key_082b = { 5c 43 [2] 28 5b [2] 6f 59 [2] 28 48 [2] 66 44 [2] 6a 4e [2] 7d 45 [2] 66 0b [2] 5b }

  condition:
    any of them
}