rule TTP_XOR_MULT_DOSStub_117b {
  strings:
    $key_117b = { 45 13 [2] 31 0b [2] 76 09 [2] 31 18 [2] 7f 14 [2] 73 1e [2] 64 15 [2] 7f 5b [2] 42 }

  condition:
    any of them
}